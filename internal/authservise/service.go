package authservise

type AuthService struct {
	Tokens Tokens
	Users  Database
}

func NewAuthService(userPath string, tokenPath string) (*AuthService, error) {
	var s AuthService

	_, err := s.Users.Open(userPath)
	if err != nil {
		return nil, err
	}

	_, err = s.Tokens.Open(tokenPath)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *AuthService) Close() {
	s.Users.Close()
	s.Tokens.Close()
}
