package consumer

import (
	"context"
	"time"

	"github.com/antihax/optional"
	"golang.org/x/oauth2"

	"github.com/free5gc/openapi"

	"github.com/free5gc/openapi/Nnrf_AccessToken"
	"github.com/free5gc/openapi/models"
	udr_context "github.com/free5gc/udr/internal/context"
	"github.com/free5gc/udr/internal/logger"
	"github.com/free5gc/udr/pkg/factory"
)

func GetTokenCtx(scope, targetNF string) (context.Context, *models.ProblemDetails, error) {
	if factory.UdrConfig.GetOAuth() {
		tok, pd, err := sendAccTokenReq(scope, targetNF)
		// udrSelf := udr_context.GetSelf()
		// tok, pd, err := util.SendAccTokenReq
		//   (udrSelf.NfId, models.NfType_UDR, &udrSelf.TokenMap, &udrSelf.ClientMap, scope, targetNF, udrSelf.NrfUri)
		if err != nil {
			return nil, pd, err
		}
		return context.WithValue(context.Background(),
			openapi.ContextOAuth2, tok), pd, nil
	}
	return context.TODO(), nil, nil
}

func sendAccTokenReq(scope, targetNF string) (oauth2.TokenSource, *models.ProblemDetails, error) {
	logger.ConsumerLog.Infof("Send Access Token Request")
	var client *Nnrf_AccessToken.APIClient
	udrSelf := udr_context.GetSelf()
	// Set client and set url
	configuration := Nnrf_AccessToken.NewConfiguration()
	configuration.SetBasePath(udrSelf.NrfUri)
	if val, ok := udrSelf.ClientMap.Load(configuration); ok {
		client = val.(*Nnrf_AccessToken.APIClient)
	} else {
		client = Nnrf_AccessToken.NewAPIClient(configuration)
		udrSelf.ClientMap.Store(configuration, client)
	}

	var tok models.AccessTokenRsp

	if val, ok := udrSelf.TokenMap.Load(scope); ok {
		tok = val.(models.AccessTokenRsp)
		if int32(time.Now().Unix()) < tok.ExpiresIn {
			logger.ConsumerLog.Infof("Token is not expired")
			token := &oauth2.Token{
				AccessToken: tok.AccessToken,
				TokenType:   tok.TokenType,
				Expiry:      time.Unix(int64(tok.ExpiresIn), 0),
			}
			return oauth2.StaticTokenSource(token), nil, nil
		}
	}

	tok, res, err := client.AccessTokenRequestApi.AccessTokenRequest(context.Background(), "client_credentials",
		udrSelf.NfId, scope, &Nnrf_AccessToken.AccessTokenRequestParamOpts{
			NfType:       optional.NewInterface(models.NfType_UDR),
			TargetNfType: optional.NewInterface(targetNF),
		})
	if err == nil {
		udrSelf.TokenMap.Store(scope, tok)
		token := &oauth2.Token{
			AccessToken: tok.AccessToken,
			TokenType:   tok.TokenType,
			Expiry:      time.Unix(int64(tok.ExpiresIn), 0),
		}
		return oauth2.StaticTokenSource(token), nil, err
	} else if res != nil {
		defer func() {
			if resCloseErr := res.Body.Close(); resCloseErr != nil {
				logger.ConsumerLog.Errorf("AccessTokenRequestApi response body cannot close: %+v", resCloseErr)
			}
		}()
		if res.Status != err.Error() {
			return nil, nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		// problem := err.(openapi.GenericOpenAPIError).Model().(models.AccessTokenErr)
		return nil, &problem, err
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}
