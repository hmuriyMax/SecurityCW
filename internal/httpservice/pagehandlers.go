package httpservice

import (
	"github.com/hmuriyMax/SecurityCW/internal/utils"
	"html/template"
	"net/http"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	indexPath := utils.HTMLpath + "index.html"
	var pageTemplate = template.Must(template.ParseFiles(indexPath))

	cookie, err := r.Cookie("token")
	if err != nil {
		utils.Redirect(w, "/auth", http.StatusTemporaryRedirect)
		return
	}
	user, err := main.tokens.Get(cookie.Value)
	if err != nil {
		utils.Redirect(w, "/auth", http.StatusTemporaryRedirect)
		return
	}

	data := make(map[string]interface{})
	if user.Su {
		data["Table"] = main.users.parsed
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

func authHandler(writer http.ResponseWriter, request *http.Request) {
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
	err := pageTemplate.Execute(writer, data)
	if err != nil {
		http.Error(writer, "Error while opening page", http.StatusInternalServerError)
	}
}

func firstSignHandler(writer http.ResponseWriter, request *http.Request) {
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
	usr, err := main.tokens.Get(token.Value)
	if err != nil {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	data["username"] = usr.Name
	login, err := main.users.GetUserByLogin(usr.Name)
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

func changePassHandler(writer http.ResponseWriter, request *http.Request) {
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
	token, err := request.Cookie("token")
	if err != nil {
		http.Error(writer, "User token not found", http.StatusInternalServerError)
		return
	}
	usr, err := main.tokens.Get(token.Value)
	if err != nil {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	data["username"] = usr.Name
	login, err := main.users.GetUserByLogin(usr.Name)
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
