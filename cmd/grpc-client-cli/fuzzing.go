package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/signal"

	"github.com/jhump/protoreflect/desc"
	"golang.org/x/exp/constraints"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

func fuzzCallFunc(method *desc.MethodDescriptor, fuzzing int, callFunc func(messages [][]byte) (bool, error)) func(messages [][]byte) (bool, error) {
	return func(messages [][]byte) (bool, error) {
		stopCh := make(chan os.Signal, 2)
		defer close(stopCh)
		signal.Notify(stopCh, os.Interrupt)
		defer signal.Stop(stopCh)
		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()
		go func() {
			<-stopCh
			cancel()
			_, ok := <-stopCh
			if ok {
				os.Exit(1)
			}
		}()

		var count int
		for count != fuzzing {
			select {
			case <-ctx.Done():
				return true, nil
			default:
				fuzzMsgs := fuzzMessages(method, messages)
				count++
				var msg string
				if len(fuzzMsgs) == 1 {
					msg = string(fuzzMsgs[0])
				} else {
					buf := bytes.Buffer{}
					buf.WriteByte('[')
					for i, v := range fuzzMsgs {
						buf.Write(v)
						if i != len(fuzzMsgs)-1 {
							buf.Write([]byte{',', ' '})
						}
					}
					buf.WriteByte(']')
					msg = buf.String()
				}
				fmt.Printf("fuzzing %d, message: %s\n", count, msg)

				if goOn, err := callFunc(fuzzMsgs); !goOn {
					return goOn, err
				}
			}
		}

		return true, nil
	}
}

func fuzzMessages(desc *desc.MethodDescriptor, messages [][]byte) [][]byte {
	newMessages := make([][]byte, len(messages))
	for i, v := range messages {
		newMessages[i] = make([]byte, len(v))
		copy(newMessages[i], v)
	}

	inputMsg := desc.UnwrapMethod().Input()
	for i, data := range newMessages {
		kv := map[string]any{}
		_ = json.Unmarshal(data, &kv)
		msg := dynamicpb.NewMessage(inputMsg)
		_ = protojson.Unmarshal(data, msg)
		fuzzMessage(inputMsg, msg, kv)

		newData, _ := protojson.Marshal(msg)
		newMessages[i] = newData
	}

	return newMessages
}

func randMakeNegative[T constraints.Signed | constraints.Float](i T) T {
	if rand.Int()%2 == 0 {
		return -i
	}
	return i
}

func randASCIIBytes(length int) []byte {
	ret := make([]byte, length)
	for i := range length {
		ret[i] = byte(rand.Intn(95) + 32)
	}

	return ret
}

func fuzzMessage(msgDesc protoreflect.MessageDescriptor, msg *dynamicpb.Message, kv map[string]any) {
	fields := msgDesc.Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		fieldValue := msg.Get(field)
		if field.Kind() != protoreflect.MessageKind && field.Kind() != protoreflect.GroupKind {
			if _, ok := kv[field.TextName()]; ok {
				continue
			}
			if _, ok := kv[field.JSONName()]; ok {
				continue
			}
		}

		fuzzProtoField(field, fieldValue, msg, kv)
	}
}

func fuzzProtoField(field protoreflect.FieldDescriptor, fieldValue protoreflect.Value, msg *dynamicpb.Message, kv map[string]any) {
	switch {
	case field.IsList():
		fieldValue = msg.NewField(field)
		list := fieldValue.List()
		for range rand.Intn(10) {
			list.Append(fuzzData(field, list.NewElement(), kv))
		}
	case field.IsMap():
		fieldValue = msg.NewField(field)
		m := fieldValue.Map()
		for range rand.Intn(10) {
			m.Set(protoreflect.MapKey(fuzzData(field.MapKey(), protoreflect.Value{}, kv)), fuzzData(field.MapValue(), m.NewValue(), kv))
		}
	case field.Message() != nil:
		fieldValue = fuzzData(field, msg.Mutable(field), kv)
	default:
		fieldValue = fuzzData(field, fieldValue, kv)
	}

	msg.Set(field, fieldValue)
}

func fuzzData(field protoreflect.FieldDescriptor, fieldValue protoreflect.Value, kv map[string]any) protoreflect.Value {
	switch field.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(rand.Int()%2 == 0)
	case protoreflect.EnumKind:
		return protoreflect.ValueOfEnum(protoreflect.EnumNumber(randMakeNegative(rand.Int31())))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(randMakeNegative(rand.Int31()))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(rand.Uint32())
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(randMakeNegative(rand.Int63()))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(rand.Uint64())
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat64(randMakeNegative(rand.Float64()))
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat32(randMakeNegative(rand.Float32()))
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(string(randASCIIBytes(rand.Intn(64))))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(randASCIIBytes(rand.Intn(64)))
	case protoreflect.MessageKind, protoreflect.GroupKind:
		subMsg := fieldValue.Message().(*dynamicpb.Message)
		if kv, ok := kv[field.TextName()]; ok {
			fuzzMessage(field.Message(), subMsg, kv.(map[string]any))
			return fieldValue
		}
		if kv, ok := kv[field.JSONName()]; ok {
			fuzzMessage(field.Message(), subMsg, kv.(map[string]any))
			return fieldValue
		}

		fuzzMessage(field.Message(), subMsg, map[string]any{})
		return fieldValue
	default:
		return protoreflect.Value{}
	}
}
