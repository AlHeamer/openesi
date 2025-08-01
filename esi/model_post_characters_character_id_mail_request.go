/*
EVE Stellar Information (ESI) - tranquility

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2020-01-01
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package esi

import (
	"encoding/json"
	"bytes"
	"fmt"
)

// checks if the PostCharactersCharacterIdMailRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &PostCharactersCharacterIdMailRequest{}

// PostCharactersCharacterIdMailRequest struct for PostCharactersCharacterIdMailRequest
type PostCharactersCharacterIdMailRequest struct {
	ApprovedCost *int64 `json:"approved_cost,omitempty"`
	Body string `json:"body"`
	Recipients []PostCharactersCharacterIdMailRequestRecipientsInner `json:"recipients"`
	Subject string `json:"subject"`
}

type _PostCharactersCharacterIdMailRequest PostCharactersCharacterIdMailRequest

// NewPostCharactersCharacterIdMailRequest instantiates a new PostCharactersCharacterIdMailRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPostCharactersCharacterIdMailRequest(body string, recipients []PostCharactersCharacterIdMailRequestRecipientsInner, subject string) *PostCharactersCharacterIdMailRequest {
	this := PostCharactersCharacterIdMailRequest{}
	var approvedCost int64 = 0
	this.ApprovedCost = &approvedCost
	this.Body = body
	this.Recipients = recipients
	this.Subject = subject
	return &this
}

// NewPostCharactersCharacterIdMailRequestWithDefaults instantiates a new PostCharactersCharacterIdMailRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPostCharactersCharacterIdMailRequestWithDefaults() *PostCharactersCharacterIdMailRequest {
	this := PostCharactersCharacterIdMailRequest{}
	var approvedCost int64 = 0
	this.ApprovedCost = &approvedCost
	return &this
}

// GetApprovedCost returns the ApprovedCost field value if set, zero value otherwise.
func (o *PostCharactersCharacterIdMailRequest) GetApprovedCost() int64 {
	if o == nil || IsNil(o.ApprovedCost) {
		var ret int64
		return ret
	}
	return *o.ApprovedCost
}

// GetApprovedCostOk returns a tuple with the ApprovedCost field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PostCharactersCharacterIdMailRequest) GetApprovedCostOk() (*int64, bool) {
	if o == nil || IsNil(o.ApprovedCost) {
		return nil, false
	}
	return o.ApprovedCost, true
}

// HasApprovedCost returns a boolean if a field has been set.
func (o *PostCharactersCharacterIdMailRequest) HasApprovedCost() bool {
	if o != nil && !IsNil(o.ApprovedCost) {
		return true
	}

	return false
}

// SetApprovedCost gets a reference to the given int64 and assigns it to the ApprovedCost field.
func (o *PostCharactersCharacterIdMailRequest) SetApprovedCost(v int64) {
	o.ApprovedCost = &v
}

// GetBody returns the Body field value
func (o *PostCharactersCharacterIdMailRequest) GetBody() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Body
}

// GetBodyOk returns a tuple with the Body field value
// and a boolean to check if the value has been set.
func (o *PostCharactersCharacterIdMailRequest) GetBodyOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Body, true
}

// SetBody sets field value
func (o *PostCharactersCharacterIdMailRequest) SetBody(v string) {
	o.Body = v
}

// GetRecipients returns the Recipients field value
func (o *PostCharactersCharacterIdMailRequest) GetRecipients() []PostCharactersCharacterIdMailRequestRecipientsInner {
	if o == nil {
		var ret []PostCharactersCharacterIdMailRequestRecipientsInner
		return ret
	}

	return o.Recipients
}

// GetRecipientsOk returns a tuple with the Recipients field value
// and a boolean to check if the value has been set.
func (o *PostCharactersCharacterIdMailRequest) GetRecipientsOk() ([]PostCharactersCharacterIdMailRequestRecipientsInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.Recipients, true
}

// SetRecipients sets field value
func (o *PostCharactersCharacterIdMailRequest) SetRecipients(v []PostCharactersCharacterIdMailRequestRecipientsInner) {
	o.Recipients = v
}

// GetSubject returns the Subject field value
func (o *PostCharactersCharacterIdMailRequest) GetSubject() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Subject
}

// GetSubjectOk returns a tuple with the Subject field value
// and a boolean to check if the value has been set.
func (o *PostCharactersCharacterIdMailRequest) GetSubjectOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Subject, true
}

// SetSubject sets field value
func (o *PostCharactersCharacterIdMailRequest) SetSubject(v string) {
	o.Subject = v
}

func (o PostCharactersCharacterIdMailRequest) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o PostCharactersCharacterIdMailRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.ApprovedCost) {
		toSerialize["approved_cost"] = o.ApprovedCost
	}
	toSerialize["body"] = o.Body
	toSerialize["recipients"] = o.Recipients
	toSerialize["subject"] = o.Subject
	return toSerialize, nil
}

func (o *PostCharactersCharacterIdMailRequest) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"body",
		"recipients",
		"subject",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err;
	}

	for _, requiredProperty := range(requiredProperties) {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varPostCharactersCharacterIdMailRequest := _PostCharactersCharacterIdMailRequest{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varPostCharactersCharacterIdMailRequest)

	if err != nil {
		return err
	}

	*o = PostCharactersCharacterIdMailRequest(varPostCharactersCharacterIdMailRequest)

	return err
}

type NullablePostCharactersCharacterIdMailRequest struct {
	value *PostCharactersCharacterIdMailRequest
	isSet bool
}

func (v NullablePostCharactersCharacterIdMailRequest) Get() *PostCharactersCharacterIdMailRequest {
	return v.value
}

func (v *NullablePostCharactersCharacterIdMailRequest) Set(val *PostCharactersCharacterIdMailRequest) {
	v.value = val
	v.isSet = true
}

func (v NullablePostCharactersCharacterIdMailRequest) IsSet() bool {
	return v.isSet
}

func (v *NullablePostCharactersCharacterIdMailRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePostCharactersCharacterIdMailRequest(val *PostCharactersCharacterIdMailRequest) *NullablePostCharactersCharacterIdMailRequest {
	return &NullablePostCharactersCharacterIdMailRequest{value: val, isSet: true}
}

func (v NullablePostCharactersCharacterIdMailRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePostCharactersCharacterIdMailRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


