package main

type Buffer struct {
	data  []byte
	start int
}

func (buffer *Buffer) PrependBytes(n int) []byte {
	newLength := cap(buffer.data) + n
	newData := make([]byte, newLength)

	copy(newData, buffer.data)

	buffer.start = cap(buffer.data)
	buffer.data = newData
	return buffer.data[buffer.start:]
}

func NewBuffer() *Buffer {
	return &Buffer{
	}
}

func Reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}
