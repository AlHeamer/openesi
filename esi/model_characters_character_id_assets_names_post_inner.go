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

// checks if the CharactersCharacterIdAssetsNamesPostInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CharactersCharacterIdAssetsNamesPostInner{}

// CharactersCharacterIdAssetsNamesPostInner struct for CharactersCharacterIdAssetsNamesPostInner
type CharactersCharacterIdAssetsNamesPostInner struct {
	ItemId int64 `json:"item_id"`
	Name string `json:"name"`
}

type _CharactersCharacterIdAssetsNamesPostInner CharactersCharacterIdAssetsNamesPostInner

// NewCharactersCharacterIdAssetsNamesPostInner instantiates a new CharactersCharacterIdAssetsNamesPostInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCharactersCharacterIdAssetsNamesPostInner(itemId int64, name string) *CharactersCharacterIdAssetsNamesPostInner {
	this := CharactersCharacterIdAssetsNamesPostInner{}
	this.ItemId = itemId
	this.Name = name
	return &this
}

// NewCharactersCharacterIdAssetsNamesPostInnerWithDefaults instantiates a new CharactersCharacterIdAssetsNamesPostInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCharactersCharacterIdAssetsNamesPostInnerWithDefaults() *CharactersCharacterIdAssetsNamesPostInner {
	this := CharactersCharacterIdAssetsNamesPostInner{}
	return &this
}

// GetItemId returns the ItemId field value
func (o *CharactersCharacterIdAssetsNamesPostInner) GetItemId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.ItemId
}

// GetItemIdOk returns a tuple with the ItemId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAssetsNamesPostInner) GetItemIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ItemId, true
}

// SetItemId sets field value
func (o *CharactersCharacterIdAssetsNamesPostInner) SetItemId(v int64) {
	o.ItemId = v
}

// GetName returns the Name field value
func (o *CharactersCharacterIdAssetsNamesPostInner) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAssetsNamesPostInner) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *CharactersCharacterIdAssetsNamesPostInner) SetName(v string) {
	o.Name = v
}

func (o CharactersCharacterIdAssetsNamesPostInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CharactersCharacterIdAssetsNamesPostInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["item_id"] = o.ItemId
	toSerialize["name"] = o.Name
	return toSerialize, nil
}

func (o *CharactersCharacterIdAssetsNamesPostInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"item_id",
		"name",
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

	varCharactersCharacterIdAssetsNamesPostInner := _CharactersCharacterIdAssetsNamesPostInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCharactersCharacterIdAssetsNamesPostInner)

	if err != nil {
		return err
	}

	*o = CharactersCharacterIdAssetsNamesPostInner(varCharactersCharacterIdAssetsNamesPostInner)

	return err
}

type NullableCharactersCharacterIdAssetsNamesPostInner struct {
	value *CharactersCharacterIdAssetsNamesPostInner
	isSet bool
}

func (v NullableCharactersCharacterIdAssetsNamesPostInner) Get() *CharactersCharacterIdAssetsNamesPostInner {
	return v.value
}

func (v *NullableCharactersCharacterIdAssetsNamesPostInner) Set(val *CharactersCharacterIdAssetsNamesPostInner) {
	v.value = val
	v.isSet = true
}

func (v NullableCharactersCharacterIdAssetsNamesPostInner) IsSet() bool {
	return v.isSet
}

func (v *NullableCharactersCharacterIdAssetsNamesPostInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCharactersCharacterIdAssetsNamesPostInner(val *CharactersCharacterIdAssetsNamesPostInner) *NullableCharactersCharacterIdAssetsNamesPostInner {
	return &NullableCharactersCharacterIdAssetsNamesPostInner{value: val, isSet: true}
}

func (v NullableCharactersCharacterIdAssetsNamesPostInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCharactersCharacterIdAssetsNamesPostInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


