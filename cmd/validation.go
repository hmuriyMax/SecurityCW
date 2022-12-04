package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"
)

type Token struct {
	Name string
	Su   bool
}

type Tokens struct {
	filepath string
	list     map[string]Token
	num      int
}

func generateToken(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func (t *Tokens) Parse() error {
	if t.filepath == "" {
		return fmt.Errorf("Database was never opened\n")
	}
	bytes, err := os.ReadFile(t.filepath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytes, &t.list)
	if err != nil {
		_, err = os.Create(t.filepath)
		if err != nil {
			log.Printf("Error while creating db at %s...\n", t.filepath)
			return err
		}
	}
	return nil
}

func (t *Tokens) Open(filepath string) (bool, error) {
	t.num = 0
	t.list = make(map[string]Token)
	fl := false
	t.filepath = filepath
	file, err := os.Open(t.filepath)
	defer func() { _ = file.Close() }()
	if err != nil {
		log.Printf("Database not found at %s\nTrying to create one...\n", t.filepath)
		file, err = os.Create(t.filepath)
		if err != nil {
			log.Printf("Error while creating db at %s...\n", t.filepath)
			return false, err
		}
		fl = true
	} else {
		err := t.Parse()
		if err != nil {
			return false, err
		}
	}
	return fl, nil
}

func (t *Tokens) Add(name string, su bool) string {
	var token string
	for {
		token = generateToken(15)
		if _, ok := (*t).list[token]; !ok {
			break
		}
	}
	t.list[token] = Token{Name: name, Su: su}
	t.num++
	return token
}

func (t *Tokens) Get(token string) (Token, error) {
	t2, ok := t.list[token]
	if !ok {
		return Token{}, errors.New("No token in database")
	}
	return t2, nil
}

func (t *Tokens) Delete(token string) {
	_, ok := t.list[token]
	if !ok {
		return
	}
	delete(t.list, token)
}

func (t *Tokens) Close() {
	file, err := os.OpenFile(t.filepath, os.O_WRONLY|os.O_TRUNC, 0777)
	defer func() { _ = file.Close() }()

	if err != nil {
		log.Fatal(err)
	}

	marshal, err := json.MarshalIndent(t.list, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	_, err = fmt.Fprint(file, string(marshal))
	if err != nil {
		log.Fatal(err)
	}
	t.filepath = ""
}
