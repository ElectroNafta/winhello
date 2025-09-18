//go:build windows

package winhello

import (
	"errors"
	"log/slog"
	"unsafe"

	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"golang.org/x/sys/windows"
)

var (
	modWebAuthn                                               = windows.NewLazyDLL("webauthn.dll")
	procWebAuthNAuthenticatorGetAssertion                     = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procWebAuthNFreeAssertion                                 = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procWebAuthNGetApiVersionNumber                           = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable = modWebAuthn.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	currVer                                                   = availableVersions(APIVersionNumber())
)

type WebAuthnCredentialDetails struct {
	CredentialID []byte
	RP           webauthntypes.PublicKeyCredentialRpEntity
	User         webauthntypes.PublicKeyCredentialUserEntity
	Removable    bool
	BackedUp     bool
}

func GetAssertion(
	hWnd windows.HWND,
	rpID string,
	clientData []byte,
	allowList []webauthntypes.PublicKeyCredentialDescriptor,
	extInputs *webauthntypes.GetAuthenticationExtensionsClientInputs,
	winHelloOpts *AuthenticatorGetAssertionOptions,
) (*WinHelloGetAssertionResponse, error) {
	if winHelloOpts == nil {
		winHelloOpts = &AuthenticatorGetAssertionOptions{}
	}

	opts := &WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS{
		DwVersion:                     currVer.authenticatorGetAssertionOptions,
		DwTimeoutMilliseconds:         uint32(winHelloOpts.Timeout.Milliseconds()),
		CredentialList:                WEBAUTHN_CREDENTIALS{}, // basically deprecated, baseline supports pAllowCredentialList
		DwAuthenticatorAttachment:     uint32(winHelloOpts.AuthenticatorAttachment),
		DwUserVerificationRequirement: uint32(winHelloOpts.UserVerificationRequirement),
		DwFlags:                       0, // user only in version 8 for PRF Global Eval
		DwCredLargeBlobOperation:      uint32(winHelloOpts.CredentialLargeBlobOperation),
		CbCredLargeBlob:               uint32(len(winHelloOpts.CredentialLargeBlob)),
		PbCredLargeBlob:               unsafe.SliceData(winHelloOpts.CredentialLargeBlob),
	}

	credExList := make([]*WEBAUTHN_CREDENTIAL_EX, len(allowList))
	for i, ex := range allowList {
		dwTransports := uint32(0)
		for _, tr := range ex.Transports {
			switch tr {
			case webauthntypes.AuthenticatorTransportUSB:
				dwTransports |= uint32(WinHelloCTAPTransportUSB)
			case webauthntypes.AuthenticatorTransportNFC:
				dwTransports |= uint32(WinHelloCTAPTransportNFC)
			case webauthntypes.AuthenticatorTransportBLE:
				dwTransports |= uint32(WinHelloCTAPTransportBLE)
			case webauthntypes.AuthenticatorTransportSmartCard:
			case webauthntypes.AuthenticatorTransportHybrid:
				dwTransports |= uint32(WinHelloCTAPTransportHybrid)
			case webauthntypes.AuthenticatorTransportInternal:
				dwTransports |= uint32(WinHelloCTAPTransportInternal)
			}
		}

		credExList[i] = &WEBAUTHN_CREDENTIAL_EX{
			DwVersion:          currVer.credentialEx,
			CbId:               uint32(len(ex.ID)),
			PbId:               unsafe.SliceData(ex.ID),
			PwszCredentialType: windows.StringToUTF16Ptr(string(ex.Type)),
			DwTransports:       dwTransports,
		}
	}
	if len(credExList) > 0 {
		opts.PAllowCredentialList = &WEBAUTHN_CREDENTIAL_LIST{
			CCredentials:  uint32(len(credExList)),
			PpCredentials: unsafe.SliceData(credExList),
		}
	}

	if winHelloOpts.CancellationID != nil {
		opts.PCancellationId = &GUID{
			Data1: winHelloOpts.CancellationID.Data1,
			Data2: winHelloOpts.CancellationID.Data2,
			Data3: winHelloOpts.CancellationID.Data3,
			Data4: winHelloOpts.CancellationID.Data4,
		}
	}

	if winHelloOpts.U2FAppID != "" {
		opts.PwszU2fAppId = windows.StringToUTF16Ptr(winHelloOpts.U2FAppID)
		t := boolToInt32(true)
		opts.PbU2fAppId = &t
	}

	if winHelloOpts.CredentialHints != nil {
		credHints := make([]*uint16, len(winHelloOpts.CredentialHints))
		for i, hint := range winHelloOpts.CredentialHints {
			credHints[i] = windows.StringToUTF16Ptr(string(hint))
		}
	}

	if extInputs != nil {
		exts := make([]WEBAUTHN_EXTENSION, 0)

		// credBlob
		if extInputs.GetCredentialBlobInputs != nil {
			ext := WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(webauthntypes.ExtensionIdentifierCredentialBlob)),
			}

			credBlob := boolToInt32(extInputs.GetCredentialBlobInputs.GetCredBlob)
			ext.CbExtension = uint32(unsafe.Sizeof(credBlob))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credBlob))
			exts = append(exts, ext)
		}

		// check that only hmac-secret or prf was supplied
		if extInputs.GetHMACSecretInputs != nil && extInputs.PRFInputs != nil {
			return nil, errors.New("you cannot use hmac-secret and prf extensions at the same time")
		}

		opts.Extensions = WEBAUTHN_EXTENSIONS{
			CExtensions: uint32(len(exts)),
			PExtensions: unsafe.SliceData(exts),
		}
	}

	assertionPtr := new(WEBAUTHN_ASSERTION)

	r1, _, _ := procWebAuthNAuthenticatorGetAssertion.Call(
		uintptr(hWnd),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(rpID))),
		uintptr(unsafe.Pointer(&WEBAUTHN_CLIENT_DATA{
			DwVersion:        currVer.clientData,
			CbClientDataJSON: uint32(len(clientData)),
			PbClientDataJSON: unsafe.SliceData(clientData),
			PwszHashAlgId:    windows.StringToUTF16Ptr("SHA-256"),
		})),
		uintptr(unsafe.Pointer(opts)),
		uintptr(unsafe.Pointer(&assertionPtr)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	defer func() {
		_, _, err := procWebAuthNFreeAssertion.Call(uintptr(unsafe.Pointer(assertionPtr)))
		if err != nil && !errors.Is(err, windows.NTE_OP_OK) {
			slog.Debug("Assertion free failed!", "err", err)
		}
	}()

	resp, err := assertionPtr.ToGetAssertionResponse()
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func APIVersionNumber() uint32 {
	r1, _, _ := procWebAuthNGetApiVersionNumber.Call()
	return uint32(r1)
}

func IsUserVerifyingPlatformAuthenticatorAvailable() (bool, error) {
	var isAvailable bool

	r1, _, _ := procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.Call(
		uintptr(unsafe.Pointer(&isAvailable)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return false, windows.Errno(hr)
	}

	return isAvailable, nil
}
