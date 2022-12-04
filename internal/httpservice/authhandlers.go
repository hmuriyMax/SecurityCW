package httpservice

import (
	"github.com/hmuriyMax/SecurityCW/internal/authservise"
	"github.com/hmuriyMax/SecurityCW/internal/utils"
	"log"
	"net/http"
	"strings"
)

func (s *HTTPService) checkLogHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "Not valid method", http.StatusMethodNotAllowed)
	}
	err := request.ParseForm()
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		log.Println(err)
	}
	login := strings.ToLower(request.PostForm.Get("login"))
	password := request.PostForm.Get("password")

	gotUser, err := s.auth.Users.GetUserByLogin(login)
	if err != nil {
		utils.Redirect(writer, "/auth?mess=unauth&uname="+login, http.StatusSeeOther)
		return
	}
	gotUser.NumOfTrys++
	gotUser.IsBlocked = gotUser.IsBlocked || gotUser.NumOfTrys >= 3
	if gotUser.IsBlocked {
		utils.Redirect(writer, "/auth?mess=blocked&uname="+login, http.StatusSeeOther)
		return
	}

	// Проверка на равенство сохраненного хеша и хеша полученного пароля
	if gotUser.Pass != utils.Hash27(password) {
		utils.Redirect(writer, "/auth?mess=unauth&uname="+login, http.StatusSeeOther)
		return
	}

	gotUser.NumOfTrys = 0
	if _, err := request.Cookie("token"); err == nil {
		utils.DelCookie(writer, "token")
	}
	utils.SetCookie(writer, "token", s.auth.Tokens.Add(login, s.auth.Users.GetAllUsers()[0].Login == login), int(utils.CookiesAge))

	if password == "" {
		utils.Redirect(writer, "/firstsign", http.StatusTemporaryRedirect)
		return
	}
	utils.Redirect(writer, "/", http.StatusFound)
}

func (s *HTTPService) logoutHandler(writer http.ResponseWriter, request *http.Request) {
	tok, err := request.Cookie("token")
	if err == nil {
		utils.DelCookie(writer, "token")
	}
	s.auth.Tokens.Delete(tok.Value)
	utils.Redirect(writer, "/", http.StatusFound)
}

func (s *HTTPService) newPassHandler(writer http.ResponseWriter, request *http.Request) {
	token, err := request.Cookie("token")
	if err != nil {
		http.Error(writer, "User token not found", http.StatusInternalServerError)
		return
	}
	tkn, err := s.auth.Tokens.Get(token.Value)
	if err != nil {
		return
	}

	if request.Method != http.MethodPost {
		http.Error(writer, "Not valid method", http.StatusMethodNotAllowed)
	}
	err = request.ParseForm()
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		log.Println(err)
	}

	opass := request.PostForm.Get("oldpass")
	pass1 := request.PostForm.Get("pass1")
	pass2 := request.PostForm.Get("pass2")

	if pass1 != pass2 {
		utils.Redirect(writer, request.Referer()+"?mess=unmtch", http.StatusTemporaryRedirect)
		return
	}
	usr, err := s.auth.Users.GetUserByLogin(tkn.Name)

	if err != nil {
		http.Error(writer, "User not found!", http.StatusInternalServerError)
		return
	}

	if usr.PassRestr && pass1 == utils.Reverse(usr.Login) || len(pass1) < 4 || len(pass1) > 20 {
		utils.Redirect(writer, request.Referer()+"?mess=incorr", http.StatusTemporaryRedirect)
		return
	}
	if utils.Hash27(opass) != usr.Pass {
		utils.Redirect(writer, request.Referer()+"?mess=opass", http.StatusTemporaryRedirect)
		return
	}
	// Сохранение хеша пароля
	usr.Pass = utils.Hash27(pass1)
	utils.Redirect(writer, "/", http.StatusFound)
}

func (s *HTTPService) adduserHandler(writer http.ResponseWriter, request *http.Request) {
	token, err := request.Cookie("token")
	if err != nil {
		http.Error(writer, "User token not found", http.StatusInternalServerError)
		return
	}
	tkn, err := s.auth.Tokens.Get(token.Value)
	if err != nil {
		return
	}

	if request.Method != http.MethodPost {
		http.Error(writer, "Not valid method", http.StatusMethodNotAllowed)
	}
	err = request.ParseForm()
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		log.Println(err)
	}
	newUser := strings.ToLower(request.PostForm.Get("username"))

	if newUser == "" {
		utils.Redirect(writer, "/?mess=empty", http.StatusFound)
	}
	_, err = s.auth.Users.GetUserByLogin(newUser)
	if err == nil {
		utils.Redirect(writer, "/?mess=exists", http.StatusFound)
		return
	}
	if !tkn.Su {
		http.Error(writer, "Not superuser!", http.StatusUnauthorized)
		return
	}

	user := authservise.User{newUser, "", false, true, false, 0}
	err = s.auth.Users.Append(&user)
	if err != nil {
		return
	}
	utils.Redirect(writer, "/", http.StatusFound)
}

func (s *HTTPService) changeRestrHandler(writer http.ResponseWriter, request *http.Request) {
	token, err := request.Cookie("token")
	if err != nil {
		http.Error(writer, "User token not found", http.StatusInternalServerError)
	}
	tkn, err := s.auth.Tokens.Get(token.Value)
	if err != nil {
		http.Error(writer, "Not found in token table", http.StatusInternalServerError)
	}

	if !tkn.Su {
		http.Error(writer, "Not superuser!", http.StatusUnauthorized)
	}

	username := request.URL.Query().Get("user")

	login, err := s.auth.Users.GetUserByLogin(username)
	if err != nil {
		http.Error(writer, "User not found", http.StatusInternalServerError)
	}

	login.PassRestr = !login.PassRestr

	utils.Redirect(writer, request.Referer(), http.StatusFound)
}

func (s *HTTPService) changeBlockHandler(writer http.ResponseWriter, request *http.Request) {
	token, err := request.Cookie("token")
	if err != nil {
		http.Error(writer, "User token not found", http.StatusInternalServerError)
	}
	tkn, err := s.auth.Tokens.Get(token.Value)
	if err != nil {
		http.Error(writer, "Not found in token table", http.StatusInternalServerError)
	}

	if !tkn.Su {
		http.Error(writer, "Not superuser!", http.StatusUnauthorized)
	}

	username := request.URL.Query().Get("user")

	login, err := s.auth.Users.GetUserByLogin(username)
	if err != nil {
		http.Error(writer, "User not found", http.StatusInternalServerError)
	}

	login.IsBlocked = !login.IsBlocked

	utils.Redirect(writer, request.Referer(), http.StatusFound)
}
