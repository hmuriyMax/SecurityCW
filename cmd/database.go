package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

type User struct {
	Login       string
	Pass        string
	IsBlocked   bool
	PassRestr   bool
	IsSuperuser bool
	NumOfTrys   int
}

type Database struct {
	logged         bool
	masterPassword string
	filepath       string
	parsed         []*User
}

func (db *Database) Create() error {
	_, err := os.Create(db.filepath)
	if db.masterPassword == "" {
		_, _ = fmt.Print("Come up with master password: ")
		_, _ = fmt.Scanln(&db.masterPassword)
		db.logged = true
	}
	if err != nil {
		log.Printf("Error while creating db at %s...\n", db.filepath)
		return err
	}
	db.parsed = append(db.parsed, &User{Login: "admin", IsSuperuser: true, PassRestr: true})
	return nil
}

func (db *Database) Open(filepath string) (bool, error) {
	fl := false
	db.filepath = filepath
	file, err := os.Open(db.filepath)
	defer func() { _ = file.Close() }()
	if err != nil {
		log.Printf("Database not found at %s\nTrying to create one...\n", db.filepath)
		err := db.Create()
		if err != nil {
			return false, err
		}
		fl = true
	} else {
		err := db.Parse()
		if err != nil {
			return false, err
		}
	}
	return fl, nil
}

func (db *Database) Parse() error {
	if db.filepath == "" {
		return fmt.Errorf("Database was never opened\n")
	}
	bytes, err := os.ReadFile(db.filepath)

	// Security part
	fmt.Printf("Enter master password: ")
	_, _ = fmt.Scanln(&db.masterPassword)
	bytes, err = Decrypt(bytes, md5.Sum([]byte(db.masterPassword)))
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes[:len(bytes)-16], &db.parsed)
	if err != nil {
		return errors.New("wrong password entered or failed to parse database: " + err.Error())
	}
	log.Println("file unmarshalled successfully")
	return nil
}

func (db *Database) Append(user *User) error {
	db.parsed = append(db.parsed, user)
	return nil
}

func (db *Database) Edit(user *User) error {
	gotUser, err := db.GetUserByLogin(user.Login)
	if err != nil {
		return err
	}
	*gotUser = *user
	return nil
}

func (db *Database) GetUserByLogin(login string) (*User, error) {
	for _, el := range db.parsed {
		if el.Login == login {
			return el, nil
		}
	}
	return nil, errors.New("User not found!\n")
}

func (db *Database) GetAllUsers() []*User {
	return db.parsed
}

func (db *Database) Close() {
	file, err := os.OpenFile(db.filepath, os.O_WRONLY, 0777)
	defer func() { _ = file.Close() }()

	if err != nil {
		log.Fatal(err)
	}

	marshal, err := json.MarshalIndent(db.parsed, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	// Security part
	bytes, err := Encrypt(marshal, md5.Sum([]byte(db.masterPassword)))
	if err != nil {
		log.Printf("Failed to encrypt: %s. Saving unencrypted version for backup", err)
		bytes = marshal
	}

	_, err = fmt.Fprint(file, string(bytes))
	if err != nil {
		log.Fatal(err)
	}
	db.filepath = ""
}

func Encrypt(plaintext []byte, passwordHash [16]byte) ([]byte, error) {
	//key := md5.Sum(password)
	//log.Printf("key: %s\n", key)
	block, err := aes.NewCipher(passwordHash[:])
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func Decrypt(tCipher []byte, passwordHash [16]byte) ([]byte, error) {
	//key := md5.Sum(password)
	//log.Printf("key: %s\n", key)
	block, err := aes.NewCipher(passwordHash[:])
	if err != nil {
		return nil, err
	}

	iv := tCipher[:aes.BlockSize]

	plaintext2 := make([]byte, len(tCipher))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(plaintext2, tCipher[aes.BlockSize:])
	return plaintext2, nil
}
