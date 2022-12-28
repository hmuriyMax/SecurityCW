package httpservice

import (
	"github.com/hmuriyMax/SecurityCW/internal/authservise"
	"github.com/hmuriyMax/SecurityCW/internal/utils"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (s *HTTPService) checkLogHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "Not valid method", http.StatusMethodNotAllowed)
	}
	err := request.ParseForm()
	if err != nil {
		log.Println(err)
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
	login := strings.ToLower(request.PostForm.Get("login"))
	letter := request.PostForm.Get("letter")
	number := request.PostForm.Get("number")

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

	// Проверка на равенство количества букв letter и переданного числа
	num, err := strconv.Atoi(number)
	if err != nil {
		utils.Redirect(writer, "/auth?mess=unauth&uname="+login, http.StatusSeeOther)
		return
	}
	correct := strings.Count(gotUser.Pass, letter)
	if !(correct-s.auth.Offset <= num && num <= correct+s.auth.Offset) {
		utils.Redirect(writer, "/auth?mess=unauth&uname="+login, http.StatusSeeOther)
		return
	}

	gotUser.NumOfTrys = 0
	if _, err := request.Cookie("token"); err == nil {
		utils.DelCookie(writer, "token")
	}
	utils.SetCookie(writer, "token", s.auth.Tokens.Add(login, s.auth.Users.GetAllUsers()[0].Login == login), int(utils.CookiesAge))

	if gotUser.Pass == "" {
		utils.Redirect(writer, "/firstsign", http.StatusTemporaryRedirect)
		return
	}
	utils.Redirect(writer, "/", http.StatusFound)
}

func (s *HTTPService) logoutHandler(writer http.ResponseWriter, request *http.Request) {
	tok, err := request.Cookie("token")
	if err == nil {
		utils.DelCookie(writer, "token")
		s.auth.Tokens.Delete(tok.Value)
	}
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

	pass := request.PostForm.Get("pass")

	usr, err := s.auth.Users.GetUserByLogin(tkn.Name)
	if err != nil {
		http.Error(writer, "User not found!", http.StatusInternalServerError)
		return
	}

	if usr.PassRestr && pass == utils.Reverse(usr.Login) || len(pass) < 4 || len(pass) > 20 {
		utils.Redirect(writer, request.Referer()+"?mess=incorr", http.StatusTemporaryRedirect)
		return
	}
	// Сохранение хеша пароля
	usr.Pass = pass
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

	user := authservise.User{newUser, "", false, false, false, 0}
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
	login.NumOfTrys = 0

	utils.Redirect(writer, request.Referer(), http.StatusFound)
}

func (s *HTTPService) changeSettingsHandler(writer http.ResponseWriter, request *http.Request) {
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

	err = request.ParseForm()
	if err != nil || request.Method != http.MethodPost {
		http.Error(writer, "Request error", http.StatusBadRequest)
	}

	newSymLength, err := strconv.Atoi(request.PostFormValue("symlen"))
	if err != nil || newSymLength < 1 {
		http.Error(writer, "new length is incorrect", http.StatusBadRequest)
	}

	newOffset, err := strconv.Atoi(request.PostFormValue("offset"))
	if err != nil || newOffset < 0 {
		http.Error(writer, "new offset is incorrect", http.StatusBadRequest)
	}
	s.auth.SymLength = newSymLength
	s.auth.Offset = newOffset

	utils.Redirect(writer, request.Referer(), http.StatusFound)
}
