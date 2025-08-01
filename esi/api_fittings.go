/*
EVE Stellar Information (ESI) - tranquility

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2020-01-01
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package esi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)


// FittingsAPIService FittingsAPI service
type FittingsAPIService service

type ApiDeleteCharactersCharacterIdFittingsFittingIdRequest struct {
	ctx context.Context
	ApiService *FittingsAPIService
	characterId int64
	fittingId int64
	xCompatibilityDate *string
	acceptLanguage *string
	ifNoneMatch *string
	xTenant *string
}

// The compatibility date for the request.
func (r ApiDeleteCharactersCharacterIdFittingsFittingIdRequest) XCompatibilityDate(xCompatibilityDate string) ApiDeleteCharactersCharacterIdFittingsFittingIdRequest {
	r.xCompatibilityDate = &xCompatibilityDate
	return r
}

// The language to use for the response. Defaults to &#39;en&#39;.
func (r ApiDeleteCharactersCharacterIdFittingsFittingIdRequest) AcceptLanguage(acceptLanguage string) ApiDeleteCharactersCharacterIdFittingsFittingIdRequest {
	r.acceptLanguage = &acceptLanguage
	return r
}

// The ETag of the previous request. A 304 will be returned if this matches the current ETag.
func (r ApiDeleteCharactersCharacterIdFittingsFittingIdRequest) IfNoneMatch(ifNoneMatch string) ApiDeleteCharactersCharacterIdFittingsFittingIdRequest {
	r.ifNoneMatch = &ifNoneMatch
	return r
}

// The tenant ID for the request. Defaults to &#39;tranquility&#39;.
func (r ApiDeleteCharactersCharacterIdFittingsFittingIdRequest) XTenant(xTenant string) ApiDeleteCharactersCharacterIdFittingsFittingIdRequest {
	r.xTenant = &xTenant
	return r
}

func (r ApiDeleteCharactersCharacterIdFittingsFittingIdRequest) Execute() (interface{}, *http.Response, error) {
	return r.ApiService.DeleteCharactersCharacterIdFittingsFittingIdExecute(r)
}

/*
DeleteCharactersCharacterIdFittingsFittingId Delete fitting

Delete a fitting from a character

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param characterId The ID of the character
 @param fittingId
 @return ApiDeleteCharactersCharacterIdFittingsFittingIdRequest
*/
func (a *FittingsAPIService) DeleteCharactersCharacterIdFittingsFittingId(ctx context.Context, characterId int64, fittingId int64) ApiDeleteCharactersCharacterIdFittingsFittingIdRequest {
	return ApiDeleteCharactersCharacterIdFittingsFittingIdRequest{
		ApiService: a,
		ctx: ctx,
		characterId: characterId,
		fittingId: fittingId,
	}
}

// Execute executes the request
//  @return interface{}
func (a *FittingsAPIService) DeleteCharactersCharacterIdFittingsFittingIdExecute(r ApiDeleteCharactersCharacterIdFittingsFittingIdRequest) (interface{}, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodDelete
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  interface{}
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "FittingsAPIService.DeleteCharactersCharacterIdFittingsFittingId")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/characters/{character_id}/fittings/{fitting_id}"
	localVarPath = strings.Replace(localVarPath, "{"+"character_id"+"}", url.PathEscape(parameterValueToString(r.characterId, "characterId")), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"fitting_id"+"}", url.PathEscape(parameterValueToString(r.fittingId, "fittingId")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.xCompatibilityDate == nil {
		return localVarReturnValue, nil, reportError("xCompatibilityDate is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.acceptLanguage != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "Accept-Language", r.acceptLanguage, "simple", "")
	}
	if r.ifNoneMatch != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "If-None-Match", r.ifNoneMatch, "simple", "")
	}
	parameterAddToHeaderOrQuery(localVarHeaderParams, "X-Compatibility-Date", r.xCompatibilityDate, "simple", "")
	if r.xTenant != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "X-Tenant", r.xTenant, "simple", "")
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
			var v Error
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
					newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
					newErr.model = v
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiGetCharactersCharacterIdFittingsRequest struct {
	ctx context.Context
	ApiService *FittingsAPIService
	characterId int64
	xCompatibilityDate *string
	acceptLanguage *string
	ifNoneMatch *string
	xTenant *string
}

// The compatibility date for the request.
func (r ApiGetCharactersCharacterIdFittingsRequest) XCompatibilityDate(xCompatibilityDate string) ApiGetCharactersCharacterIdFittingsRequest {
	r.xCompatibilityDate = &xCompatibilityDate
	return r
}

// The language to use for the response. Defaults to &#39;en&#39;.
func (r ApiGetCharactersCharacterIdFittingsRequest) AcceptLanguage(acceptLanguage string) ApiGetCharactersCharacterIdFittingsRequest {
	r.acceptLanguage = &acceptLanguage
	return r
}

// The ETag of the previous request. A 304 will be returned if this matches the current ETag.
func (r ApiGetCharactersCharacterIdFittingsRequest) IfNoneMatch(ifNoneMatch string) ApiGetCharactersCharacterIdFittingsRequest {
	r.ifNoneMatch = &ifNoneMatch
	return r
}

// The tenant ID for the request. Defaults to &#39;tranquility&#39;.
func (r ApiGetCharactersCharacterIdFittingsRequest) XTenant(xTenant string) ApiGetCharactersCharacterIdFittingsRequest {
	r.xTenant = &xTenant
	return r
}

func (r ApiGetCharactersCharacterIdFittingsRequest) Execute() ([]CharactersCharacterIdFittingsGetInner, *http.Response, error) {
	return r.ApiService.GetCharactersCharacterIdFittingsExecute(r)
}

/*
GetCharactersCharacterIdFittings Get fittings

Return fittings of a character

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param characterId The ID of the character
 @return ApiGetCharactersCharacterIdFittingsRequest
*/
func (a *FittingsAPIService) GetCharactersCharacterIdFittings(ctx context.Context, characterId int64) ApiGetCharactersCharacterIdFittingsRequest {
	return ApiGetCharactersCharacterIdFittingsRequest{
		ApiService: a,
		ctx: ctx,
		characterId: characterId,
	}
}

// Execute executes the request
//  @return []CharactersCharacterIdFittingsGetInner
func (a *FittingsAPIService) GetCharactersCharacterIdFittingsExecute(r ApiGetCharactersCharacterIdFittingsRequest) ([]CharactersCharacterIdFittingsGetInner, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodGet
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  []CharactersCharacterIdFittingsGetInner
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "FittingsAPIService.GetCharactersCharacterIdFittings")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/characters/{character_id}/fittings"
	localVarPath = strings.Replace(localVarPath, "{"+"character_id"+"}", url.PathEscape(parameterValueToString(r.characterId, "characterId")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.xCompatibilityDate == nil {
		return localVarReturnValue, nil, reportError("xCompatibilityDate is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.acceptLanguage != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "Accept-Language", r.acceptLanguage, "simple", "")
	}
	if r.ifNoneMatch != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "If-None-Match", r.ifNoneMatch, "simple", "")
	}
	parameterAddToHeaderOrQuery(localVarHeaderParams, "X-Compatibility-Date", r.xCompatibilityDate, "simple", "")
	if r.xTenant != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "X-Tenant", r.xTenant, "simple", "")
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
			var v Error
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
					newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
					newErr.model = v
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiPostCharactersCharacterIdFittingsRequest struct {
	ctx context.Context
	ApiService *FittingsAPIService
	characterId int64
	xCompatibilityDate *string
	acceptLanguage *string
	ifNoneMatch *string
	xTenant *string
	postCharactersCharacterIdFittingsRequest *PostCharactersCharacterIdFittingsRequest
}

// The compatibility date for the request.
func (r ApiPostCharactersCharacterIdFittingsRequest) XCompatibilityDate(xCompatibilityDate string) ApiPostCharactersCharacterIdFittingsRequest {
	r.xCompatibilityDate = &xCompatibilityDate
	return r
}

// The language to use for the response. Defaults to &#39;en&#39;.
func (r ApiPostCharactersCharacterIdFittingsRequest) AcceptLanguage(acceptLanguage string) ApiPostCharactersCharacterIdFittingsRequest {
	r.acceptLanguage = &acceptLanguage
	return r
}

// The ETag of the previous request. A 304 will be returned if this matches the current ETag.
func (r ApiPostCharactersCharacterIdFittingsRequest) IfNoneMatch(ifNoneMatch string) ApiPostCharactersCharacterIdFittingsRequest {
	r.ifNoneMatch = &ifNoneMatch
	return r
}

// The tenant ID for the request. Defaults to &#39;tranquility&#39;.
func (r ApiPostCharactersCharacterIdFittingsRequest) XTenant(xTenant string) ApiPostCharactersCharacterIdFittingsRequest {
	r.xTenant = &xTenant
	return r
}

func (r ApiPostCharactersCharacterIdFittingsRequest) PostCharactersCharacterIdFittingsRequest(postCharactersCharacterIdFittingsRequest PostCharactersCharacterIdFittingsRequest) ApiPostCharactersCharacterIdFittingsRequest {
	r.postCharactersCharacterIdFittingsRequest = &postCharactersCharacterIdFittingsRequest
	return r
}

func (r ApiPostCharactersCharacterIdFittingsRequest) Execute() (*CharactersCharacterIdFittingsPost, *http.Response, error) {
	return r.ApiService.PostCharactersCharacterIdFittingsExecute(r)
}

/*
PostCharactersCharacterIdFittings Create fitting

Save a new fitting for a character

 @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 @param characterId The ID of the character
 @return ApiPostCharactersCharacterIdFittingsRequest
*/
func (a *FittingsAPIService) PostCharactersCharacterIdFittings(ctx context.Context, characterId int64) ApiPostCharactersCharacterIdFittingsRequest {
	return ApiPostCharactersCharacterIdFittingsRequest{
		ApiService: a,
		ctx: ctx,
		characterId: characterId,
	}
}

// Execute executes the request
//  @return CharactersCharacterIdFittingsPost
func (a *FittingsAPIService) PostCharactersCharacterIdFittingsExecute(r ApiPostCharactersCharacterIdFittingsRequest) (*CharactersCharacterIdFittingsPost, *http.Response, error) {
	var (
		localVarHTTPMethod   = http.MethodPost
		localVarPostBody     interface{}
		formFiles            []formFile
		localVarReturnValue  *CharactersCharacterIdFittingsPost
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "FittingsAPIService.PostCharactersCharacterIdFittings")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/characters/{character_id}/fittings"
	localVarPath = strings.Replace(localVarPath, "{"+"character_id"+"}", url.PathEscape(parameterValueToString(r.characterId, "characterId")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.xCompatibilityDate == nil {
		return localVarReturnValue, nil, reportError("xCompatibilityDate is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if r.acceptLanguage != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "Accept-Language", r.acceptLanguage, "simple", "")
	}
	if r.ifNoneMatch != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "If-None-Match", r.ifNoneMatch, "simple", "")
	}
	parameterAddToHeaderOrQuery(localVarHeaderParams, "X-Compatibility-Date", r.xCompatibilityDate, "simple", "")
	if r.xTenant != nil {
		parameterAddToHeaderOrQuery(localVarHeaderParams, "X-Tenant", r.xTenant, "simple", "")
	}
	// body params
	localVarPostBody = r.postCharactersCharacterIdFittingsRequest
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
			var v Error
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
					newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
					newErr.model = v
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}
