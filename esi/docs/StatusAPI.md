# \StatusAPI

All URIs are relative to *https://esi.evetech.net*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetStatus**](StatusAPI.md#GetStatus) | **Get** /status | Retrieve the uptime and player counts



## GetStatus

> StatusGet GetStatus(ctx).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()

Retrieve the uptime and player counts



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
	xCompatibilityDate := time.Now() // string | The compatibility date for the request.
	acceptLanguage := "en" // string | The language to use for the response. Defaults to 'en'. (optional)
	ifNoneMatch := "ifNoneMatch_example" // string | The ETag of the previous request. A 304 will be returned if this matches the current ETag. (optional)
	xTenant := "tranquility" // string | The tenant ID for the request. Defaults to 'tranquility'. (optional)

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)
	resp, r, err := apiClient.StatusAPI.GetStatus(context.Background()).XCompatibilityDate(xCompatibilityDate).AcceptLanguage(acceptLanguage).IfNoneMatch(ifNoneMatch).XTenant(xTenant).Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `StatusAPI.GetStatus``: %v\n", err)
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `GetStatus`: StatusGet
	fmt.Fprintf(os.Stdout, "Response from `StatusAPI.GetStatus`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiGetStatusRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **xCompatibilityDate** | **string** | The compatibility date for the request. | 
 **acceptLanguage** | **string** | The language to use for the response. Defaults to &#39;en&#39;. | 
 **ifNoneMatch** | **string** | The ETag of the previous request. A 304 will be returned if this matches the current ETag. | 
 **xTenant** | **string** | The tenant ID for the request. Defaults to &#39;tranquility&#39;. | 

### Return type

[**StatusGet**](StatusGet.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

