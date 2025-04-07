package main

import (
	"fmt"
	"net/http"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

var users = map[string]Login{}

func main() {
	http.HandleFunc("POST /register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if len(username) < 8 || len(password) < 8 {
		err := http.StatusNotAcceptable
		http.Error(w, "Invalid username/password", err)
		return
	}

	if _, ok := users[username]; ok {
		err := http.StatusConflict
		http.Error(w, "User already exists", err)
	}

	hashedPassword, _ := hashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}

	fmt.Fprintln(w, "User registered successfully!")
	fmt.Printf("%v\n", users)
}

func login(w http.ResponseWriter, r *http.Request) {

}

func logout(w http.ResponseWriter, r *http.Request) {

}

func protected(w http.ResponseWriter, r *http.Request) {

}
