# \MailAPI

All URIs are relative to *https://esi.evetech.net*

Method | HTTP request | Description
------------- | ------------- | -------------
[**DeleteCharactersCharacterIdMailLabelsLabelId**](MailAPI.md#DeleteCharactersCharacterIdMailLabelsLabelId) | **Delete** /characters/{character_id}/mail/labels/{label_id} | Delete a mail label
[**DeleteCharactersCharacterIdMailMailId**](MailAPI.md#DeleteCharactersCharacterIdMailMailId) | **Delete** /characters/{character_id}/mail/{mail_id} | Delete a mail
[**GetCharactersCharacterIdMail**](MailAPI.md#GetCharactersCharacterIdMail) | **Get** /characters/{character_id}/mail | Return mail headers
[**GetCharactersCharacterIdMailLabels**](MailAPI.md#GetCharactersCharacterIdMailLabels) | **Get** /characters/{character_id}/mail/labels | Get mail labels and unread counts
[**GetCharactersCharacterIdMailLists**](MailAPI.md#GetCharactersCharacterIdMailLists) | **Get** /characters/{character_id}/mail/lists | Return mailing list subscriptions
[**GetCharactersCharacterIdMailMailId**](MailAPI.md#GetCharactersCharacterIdMailMailId) | **Get** /characters/{character_id}/mail/{mail_id} | Return a mail
[**PostCharactersCharacterIdMail**](MailAPI.md#PostCharactersCharacterIdMail) | **Post** /characters/{character_id}/mail | Send a new mail
[**PostCharactersCharacterIdMailLabels**](MailAPI.md#PostCharactersCharacterIdMailLabels) | **Post** /characters/{character_id}/mail/labels | Create a mail label
[**PutCharactersCharacterIdMailMailId**](MailAPI.md#PutCharactersCharacterIdMailMailId) | **Put** /characters/{character_id}/mail/{mail_id} | Update metadata about a mail



## DeleteCharactersCharacterIdMailLabelsLabelId

> interface{} DeleteCharactersCharacterIdMailLabelsLabelId(ctx, characterId, labelId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()

Delete a mail label



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	labelId := int64(789) // int64 | 
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.DeleteCharactersCharacterIdMailLabelsLabelId(context.Background(), characterId, labelId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.DeleteCharactersCharacterIdMailLabelsLabelId``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `DeleteCharactersCharacterIdMailLabelsLabelId`: interface{}
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.DeleteCharactersCharacterIdMailLabelsLabelId`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 
**labelId** | **int64** |  | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteCharactersCharacterIdMailLabelsLabelIdRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 

### Return type

**interface{}**

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteCharactersCharacterIdMailMailId

> interface{} DeleteCharactersCharacterIdMailMailId(ctx, characterId, mailId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()

Delete a mail



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	mailId := int64(789) // int64 | 
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.DeleteCharactersCharacterIdMailMailId(context.Background(), characterId, mailId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.DeleteCharactersCharacterIdMailMailId``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `DeleteCharactersCharacterIdMailMailId`: interface{}
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.DeleteCharactersCharacterIdMailMailId`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 
**mailId** | **int64** |  | 

### Other Parameters

Other parameters are passed through a pointer to a apiDeleteCharactersCharacterIdMailMailIdRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 

### Return type

**interface{}**

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetCharactersCharacterIdMail

> []CharactersCharacterIdMailGetInner GetCharactersCharacterIdMail(ctx, characterId).XCompatibilityDate(xCompatibilityDate).Labels(labels).LastMailId(lastMailId).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()

Return mail headers



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	labels := []int64{int64(123)} // []int64 |  (optional)
	lastMailId := int64(789) // int64 |  (optional)
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.GetCharactersCharacterIdMail(context.Background(), characterId).XCompatibilityDate(xCompatibilityDate).Labels(labels).LastMailId(lastMailId).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.GetCharactersCharacterIdMail``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetCharactersCharacterIdMail`: []CharactersCharacterIdMailGetInner
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.GetCharactersCharacterIdMail`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetCharactersCharacterIdMailRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **labels** | **[]int64** |  | 
 **lastMailId** | **int64** |  | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 

### Return type

[**[]CharactersCharacterIdMailGetInner**](CharactersCharacterIdMailGetInner.md)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetCharactersCharacterIdMailLabels

> CharactersCharacterIdMailLabelsGet GetCharactersCharacterIdMailLabels(ctx, characterId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()

Get mail labels and unread counts



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.GetCharactersCharacterIdMailLabels(context.Background(), characterId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.GetCharactersCharacterIdMailLabels``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetCharactersCharacterIdMailLabels`: CharactersCharacterIdMailLabelsGet
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.GetCharactersCharacterIdMailLabels`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetCharactersCharacterIdMailLabelsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 

### Return type

[**CharactersCharacterIdMailLabelsGet**](CharactersCharacterIdMailLabelsGet.md)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetCharactersCharacterIdMailLists

> []CharactersCharacterIdMailListsGetInner GetCharactersCharacterIdMailLists(ctx, characterId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()

Return mailing list subscriptions



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.GetCharactersCharacterIdMailLists(context.Background(), characterId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.GetCharactersCharacterIdMailLists``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetCharactersCharacterIdMailLists`: []CharactersCharacterIdMailListsGetInner
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.GetCharactersCharacterIdMailLists`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetCharactersCharacterIdMailListsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 

### Return type

[**[]CharactersCharacterIdMailListsGetInner**](CharactersCharacterIdMailListsGetInner.md)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## GetCharactersCharacterIdMailMailId

> CharactersCharacterIdMailMailIdGet GetCharactersCharacterIdMailMailId(ctx, characterId, mailId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()

Return a mail



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	mailId := int64(789) // int64 | 
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.GetCharactersCharacterIdMailMailId(context.Background(), characterId, mailId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.GetCharactersCharacterIdMailMailId``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetCharactersCharacterIdMailMailId`: CharactersCharacterIdMailMailIdGet
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.GetCharactersCharacterIdMailMailId`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 
**mailId** | **int64** |  | 

### Other Parameters

Other parameters are passed through a pointer to a apiGetCharactersCharacterIdMailMailIdRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 

### Return type

[**CharactersCharacterIdMailMailIdGet**](CharactersCharacterIdMailMailIdGet.md)

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## PostCharactersCharacterIdMail

> int64 PostCharactersCharacterIdMail(ctx, characterId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).PostCharactersCharacterIdMailRequest(postCharactersCharacterIdMailRequest).Execute()

Send a new mail



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)
	postCharactersCharacterIdMailRequest := *openapiclient.NewPostCharactersCharacterIdMailRequest("Body_example", []openapiclient.PostCharactersCharacterIdMailRequestRecipientsInner{*openapiclient.NewPostCharactersCharacterIdMailRequestRecipientsInner(int64(123), "RecipientType_example")}, "Subject_example") // PostCharactersCharacterIdMailRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.PostCharactersCharacterIdMail(context.Background(), characterId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).PostCharactersCharacterIdMailRequest(postCharactersCharacterIdMailRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.PostCharactersCharacterIdMail``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `PostCharactersCharacterIdMail`: int64
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.PostCharactersCharacterIdMail`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 

### Other Parameters

Other parameters are passed through a pointer to a apiPostCharactersCharacterIdMailRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 
 **postCharactersCharacterIdMailRequest** | [**PostCharactersCharacterIdMailRequest**](PostCharactersCharacterIdMailRequest.md) |  | 

### Return type

**int64**

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## PostCharactersCharacterIdMailLabels

> int64 PostCharactersCharacterIdMailLabels(ctx, characterId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).PostCharactersCharacterIdMailLabelsRequest(postCharactersCharacterIdMailLabelsRequest).Execute()

Create a mail label



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)
	postCharactersCharacterIdMailLabelsRequest := *openapiclient.NewPostCharactersCharacterIdMailLabelsRequest("Name_example") // PostCharactersCharacterIdMailLabelsRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.PostCharactersCharacterIdMailLabels(context.Background(), characterId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).PostCharactersCharacterIdMailLabelsRequest(postCharactersCharacterIdMailLabelsRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.PostCharactersCharacterIdMailLabels``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `PostCharactersCharacterIdMailLabels`: int64
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.PostCharactersCharacterIdMailLabels`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 

### Other Parameters

Other parameters are passed through a pointer to a apiPostCharactersCharacterIdMailLabelsRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 
 **postCharactersCharacterIdMailLabelsRequest** | [**PostCharactersCharacterIdMailLabelsRequest**](PostCharactersCharacterIdMailLabelsRequest.md) |  | 

### Return type

**int64**

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## PutCharactersCharacterIdMailMailId

> interface{} PutCharactersCharacterIdMailMailId(ctx, characterId, mailId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).PutCharactersCharacterIdMailMailIdRequest(putCharactersCharacterIdMailMailIdRequest).Execute()

Update metadata about a mail



### Example

```go
package main

import (
	"context"
	"fmt"
	"os"
    "time"
	openapiclient "github.com/AlHeamer/openesi/esi"
)

func main() {
	characterId := int64(789) // int64 | The ID of the character
	mailId := int64(789) // int64 | 
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)
	putCharactersCharacterIdMailMailIdRequest := *openapiclient.NewPutCharactersCharacterIdMailMailIdRequest() // PutCharactersCharacterIdMailMailIdRequest |  (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.MailAPI.PutCharactersCharacterIdMailMailId(context.Background(), characterId, mailId).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).PutCharactersCharacterIdMailMailIdRequest(putCharactersCharacterIdMailMailIdRequest).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `MailAPI.PutCharactersCharacterIdMailMailId``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `PutCharactersCharacterIdMailMailId`: interface{}
	fmt.Fprintf(os.Stdout, "Response from `MailAPI.PutCharactersCharacterIdMailMailId`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**characterId** | **int64** | The ID of the character | 
**mailId** | **int64** |  | 

### Other Parameters

Other parameters are passed through a pointer to a apiPutCharactersCharacterIdMailMailIdRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 
 **putCharactersCharacterIdMailMailIdRequest** | [**PutCharactersCharacterIdMailMailIdRequest**](PutCharactersCharacterIdMailMailIdRequest.md) |  | 

### Return type

**interface{}**

### Authorization

[OAuth2](../README.md#OAuth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

