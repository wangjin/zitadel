package oauth

import (
	"bytes"
	"context"
	"errors"
	"github.com/mozillazg/go-pinyin"
	"github.com/zitadel/logging"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/idp"
	"golang.org/x/text/language"
	"io/ioutil"
	"net/http"

	"encoding/json"
)

var ErrCodeMissing = errors.New("no auth code provided")

var _ idp.Session = (*Session)(nil)

// Session is the [idp.Session] implementation for the OAuth2.0 provider.
type Session struct {
	AuthURL   string
	Code      string
	Tokens    *oidc.Tokens[*oidc.IDTokenClaims]
	Provider  *Provider
	AuthToken *AuthToken
}

// GetAuth implements the [idp.Session] interface.
func (s *Session) GetAuth(ctx context.Context) (string, bool) {
	logging.WithFields("AuthUrl", s.AuthURL).Info("Debug->GetAuth")
	return idp.Redirect(s.AuthURL)
}

// FetchUser implements the [idp.Session] interface.
// It will execute an OAuth 2.0 code exchange if needed to retrieve the access token,
// call the specified userEndpoint and map the received information into an [idp.User].
func (s *Session) FetchUser(ctx context.Context) (user idp.User, err error) {
	if s.AuthToken == nil {
		if err = s.authorize(ctx); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest("GET", s.Provider.userEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-acs-dingtalk-access-token", s.AuthToken.AccessToken)
	var myUser MyUser
	if err := httphelper.HttpRequest(s.Provider.RelyingParty.HttpClient(), req, &myUser); err != nil {
		return nil, err
	}

	// name格式[wang jin]
	name := pinyin.LazyConvert(myUser.DisplayName, nil)
	// 循环数组拼接
	for i := 0; i < len(name); i++ {
		myUser.PreferredUsername += name[i]
	}
	//从myUser.DisplayName截取中文姓和名
	if len(myUser.DisplayName) > 1 {
		myUser.FirstName = substringByChar(myUser.DisplayName, 1, len(myUser.DisplayName))
		myUser.LastName = substringByChar(myUser.DisplayName, 0, 1)
	}

	myUser.PhoneVerified = true
	// 如果myUser.Email为空，填充默认值
	if myUser.Email == "" {
		myUser.Email = domain.EmailAddress(myUser.PreferredUsername + "@ieemoo.com")
	}
	myUser.EmailVerified = true
	myUser.PreferredLanguage = language.Chinese

	return myUser, nil
}

type MyUser struct {
	ID                string `json:"openId"`
	FirstName         string
	LastName          string
	DisplayName       string `json:"nick"`
	Nickname          string
	PreferredUsername string              `json:""`
	Email             domain.EmailAddress `json:"email"`
	EmailVerified     bool
	Phone             domain.EmailAddress `json:"mobile"`
	PhoneVerified     bool
	PreferredLanguage language.Tag
	AvatarURL         string `json:"avatarUrl"`
	Profile           string
}

func (u MyUser) GetID() string {
	return u.ID
}

func (u MyUser) GetFirstName() string {
	return u.FirstName
}

func (u MyUser) GetLastName() string {
	return u.LastName
}

func (u MyUser) GetDisplayName() string {
	return u.DisplayName
}

func (u MyUser) GetNickname() string {
	return u.Nickname
}

func (u MyUser) GetPreferredUsername() string {
	return u.PreferredUsername
}

func (u MyUser) GetEmail() domain.EmailAddress {
	return u.Email
}

func (u MyUser) IsEmailVerified() bool {
	return true
}

func (u MyUser) GetPhone() domain.PhoneNumber {
	return domain.PhoneNumber(u.Phone)
}

func (u MyUser) IsPhoneVerified() bool {
	return true
}

func (u MyUser) GetAvatarURL() string {
	return u.AvatarURL
}

func (u MyUser) GetPreferredLanguage() language.Tag {
	return u.PreferredLanguage
}

func (u MyUser) GetProfile() string {
	return u.Profile
}

type AuthToken struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpireIn     int32  `json:"expireIn"`
}

type RequestPayload struct {
	Code         string `json:"code"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RedirectUri  string `json:"redirectUri"`
	GrantType    string `json:"grantType"`
}

func (s *Session) authorize(ctx context.Context) (err error) {
	/*if s.Code == "" {
		return ErrCodeMissing
	}
	s.Tokens, err = rp.CodeExchange[*oidc.IDTokenClaims](ctx, s.Code, s.Provider.RelyingParty)

	return err*/
	if s.Code == "" {
		return ErrCodeMissing
	}

	// 构建请求参数
	payload := &RequestPayload{
		Code:         s.Code,
		ClientId:     s.Provider.RelyingParty.OAuthConfig().ClientID,
		ClientSecret: s.Provider.RelyingParty.OAuthConfig().ClientSecret,
		RedirectUri:  s.Provider.RelyingParty.OAuthConfig().RedirectURL,
		GrantType:    "authorization_code",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	req, err := http.NewRequest("POST", "https://api.dingtalk.com/v1.0/oauth2/userAccessToken", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// 反序列化解析TokenResponse
	var tokenResp AuthToken
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return
	}

	s.AuthToken = &tokenResp

	// 根据您的需求处理tokenResp，这里简单地假设s.Tokens可以接收TokenResponse类型
	//s.Tokens = tokenResp

	return err
}

func substringByChar(s string, start, end int) string {
	var result []rune
	for i, r := range s {
		if i >= start && i < end {
			result = append(result, r)
		}
	}
	return string(result)
}
