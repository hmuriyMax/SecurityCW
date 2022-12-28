package httpservice

import (
	"fmt"
	"github.com/hmuriyMax/SecurityCW/internal/utils"
	"html/template"
	"math/rand"
	"net/http"
)

func randSymbol() byte {
	return 'A' + byte(rand.Intn(3))
}

func (s *HTTPService) indexHandler(w http.ResponseWriter, r *http.Request) {
	indexPath := utils.HTMLpath + "index.html"
	var pageTemplate = template.Must(template.ParseFiles(indexPath))

	cookie, err := r.Cookie("token")
	if err != nil {
		utils.Redirect(w, "/auth", http.StatusTemporaryRedirect)
		return
	}
	user, err := s.auth.Tokens.Get(cookie.Value)
	if err != nil {
		utils.Redirect(w, "/auth", http.StatusTemporaryRedirect)
		return
	}

	data := make(map[string]interface{})
	if user.Su {
		data["Table"] = s.auth.Users.GetAllUsers()
		settingsMap := make(map[string]interface{})
		settingsMap["Ofs"] = s.auth.Offset
		settingsMap["Len"] = s.auth.SymLength
		data["Settings"] = settingsMap
	}
	data["username"] = user.Name

	switch r.URL.Query().Get("mess") {
	case "exists":
		data["message"] = "Пользователь уже существует!"
	case "empty":
		data["message"] = "Нельзя создать пустого пользователя!"
	}

	defer func() { _ = pageTemplate.Execute(w, data) }()
}

func (s *HTTPService) authHandler(writer http.ResponseWriter, request *http.Request) {
	authPath := utils.HTMLpath + "auth.html"
	var pageTemplate = template.Must(template.ParseFiles(authPath))
	data := make(map[string]string)
	if request.URL.Query().Get("mess") == "unauth" {
		data["message"] = "Неверный логин или пароль"
	}
	if request.URL.Query().Get("mess") == "blocked" {
		data["message"] = "Вы заблокированы. Уходите."
	}
	data["username"] = request.URL.Query().Get("uname")
	data["letter"] = string(randSymbol())
	err := pageTemplate.Execute(writer, data)
	if err != nil {
		http.Error(writer, "Error while opening page", http.StatusInternalServerError)
	}
}

func (s *HTTPService) firstSignHandler(writer http.ResponseWriter, request *http.Request) {
	authPath := utils.HTMLpath + "firstauth.html"
	var pageTemplate = template.Must(template.ParseFiles(authPath))
	data := make(map[string]string)
	if request.URL.Query().Get("mess") == "unmtch" {
		data["message"] = "Пароли не совпадают"
	}
	if request.URL.Query().Get("mess") == "incorr" {
		data["message"] = "Не выполнены требования к паролю"
	}
	token, err := request.Cookie("token")
	if err != nil {
		http.Error(writer, "User token not found", http.StatusInternalServerError)
		return
	}
	usr, err := s.auth.Tokens.Get(token.Value)
	if err != nil {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	data["username"] = usr.Name

	var symbols []byte
	for i := 0; i < s.auth.SymLength; i++ {
		symbols = append(symbols, randSymbol())
	}
	data["symbols"] = fmt.Sprintf("%s", symbols)

	login, err := s.auth.Users.GetUserByLogin(usr.Name)
	if err != nil {
		http.Error(writer, "User not found", http.StatusInternalServerError)
		return
	}
	if login.PassRestr {
		data["check"] = "true"
	}
	err = pageTemplate.Execute(writer, data)
	if err != nil {
		http.Error(writer, "Error while opening page", http.StatusInternalServerError)
		return
	}
}

func (s *HTTPService) changePassHandler(writer http.ResponseWriter, request *http.Request) {
	authPath := utils.HTMLpath + "changepass.html"
	var pageTemplate = template.Must(template.ParseFiles(authPath))
	data := make(map[string]string)
	if request.URL.Query().Get("mess") == "unmtch" {
		data["message"] = "Пароли не совпадают"
	}
	if request.URL.Query().Get("mess") == "incorr" {
		data["message"] = "Не выполнены требования к паролю"
	}
	if request.URL.Query().Get("mess") == "opass" {
		data["message"] = "Старый пароль неверен"
	}

	var symbols []byte
	for i := 0; i < s.auth.SymLength; i++ {
		symbols = append(symbols, randSymbol())
	}
	data["symbols"] = fmt.Sprintf("%s", symbols)

	token, err := request.Cookie("token")
	if err != nil {
		http.Error(writer, "User token not found", http.StatusInternalServerError)
		return
	}
	usr, err := s.auth.Tokens.Get(token.Value)
	if err != nil {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	data["username"] = usr.Name
	login, err := s.auth.Users.GetUserByLogin(usr.Name)
	if err != nil {
		http.Error(writer, "User not found", http.StatusInternalServerError)
		return
	}
	if login.PassRestr {
		data["check"] = "true"
	}
	err = pageTemplate.Execute(writer, data)
	if err != nil {
		http.Error(writer, "Error while opening page", http.StatusInternalServerError)
		return
	}
}
