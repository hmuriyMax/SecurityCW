package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

const HTMLpath = "./web/"

var Age, _ = time.ParseDuration("1d")
var CookiesAge = Age.Seconds()

func Redirect(w http.ResponseWriter, url string, status int) {
	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		log.Fatal(err)
	}
	http.Redirect(w, req, url, status)
}

func SetCookie(w http.ResponseWriter, name, value string, MaxAge int) {
	tmp := http.Cookie{
		Name:   name,
		Value:  value,
		MaxAge: MaxAge,
	}
	http.SetCookie(w, &tmp)
}

func DelCookie(w http.ResponseWriter, cookieName string) {
	c := http.Cookie{
		Name:   cookieName,
		MaxAge: -1,
	}
	http.SetCookie(w, &c)
}

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Hash27 Функция хеширования из 27 варианта
func Hash27(s string) string {
	var hash uint64
	if s == "" {
		return s
	}
	for i, ch := range s {
		hash += uint64(ch * int32(i))
		hash %= 256
	}
	return fmt.Sprint(hash)
}
