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

// checks if the CharactersCharacterIdAssetsLocationsPostInnerPosition type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CharactersCharacterIdAssetsLocationsPostInnerPosition{}

// CharactersCharacterIdAssetsLocationsPostInnerPosition struct for CharactersCharacterIdAssetsLocationsPostInnerPosition
type CharactersCharacterIdAssetsLocationsPostInnerPosition struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	Z float64 `json:"z"`
}

type _CharactersCharacterIdAssetsLocationsPostInnerPosition CharactersCharacterIdAssetsLocationsPostInnerPosition

// NewCharactersCharacterIdAssetsLocationsPostInnerPosition instantiates a new CharactersCharacterIdAssetsLocationsPostInnerPosition object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCharactersCharacterIdAssetsLocationsPostInnerPosition(x float64, y float64, z float64) *CharactersCharacterIdAssetsLocationsPostInnerPosition {
	this := CharactersCharacterIdAssetsLocationsPostInnerPosition{}
	this.X = x
	this.Y = y
	this.Z = z
	return &this
}

// NewCharactersCharacterIdAssetsLocationsPostInnerPositionWithDefaults instantiates a new CharactersCharacterIdAssetsLocationsPostInnerPosition object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCharactersCharacterIdAssetsLocationsPostInnerPositionWithDefaults() *CharactersCharacterIdAssetsLocationsPostInnerPosition {
	this := CharactersCharacterIdAssetsLocationsPostInnerPosition{}
	return &this
}

// GetX returns the X field value
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) GetX() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.X
}

// GetXOk returns a tuple with the X field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) GetXOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.X, true
}

// SetX sets field value
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) SetX(v float64) {
	o.X = v
}

// GetY returns the Y field value
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) GetY() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.Y
}

// GetYOk returns a tuple with the Y field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) GetYOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Y, true
}

// SetY sets field value
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) SetY(v float64) {
	o.Y = v
}

// GetZ returns the Z field value
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) GetZ() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.Z
}

// GetZOk returns a tuple with the Z field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) GetZOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Z, true
}

// SetZ sets field value
func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) SetZ(v float64) {
	o.Z = v
}

func (o CharactersCharacterIdAssetsLocationsPostInnerPosition) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CharactersCharacterIdAssetsLocationsPostInnerPosition) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["x"] = o.X
	toSerialize["y"] = o.Y
	toSerialize["z"] = o.Z
	return toSerialize, nil
}

func (o *CharactersCharacterIdAssetsLocationsPostInnerPosition) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"x",
		"y",
		"z",
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

	varCharactersCharacterIdAssetsLocationsPostInnerPosition := _CharactersCharacterIdAssetsLocationsPostInnerPosition{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCharactersCharacterIdAssetsLocationsPostInnerPosition)

	if err != nil {
		return err
	}

	*o = CharactersCharacterIdAssetsLocationsPostInnerPosition(varCharactersCharacterIdAssetsLocationsPostInnerPosition)

	return err
}

type NullableCharactersCharacterIdAssetsLocationsPostInnerPosition struct {
	value *CharactersCharacterIdAssetsLocationsPostInnerPosition
	isSet bool
}

func (v NullableCharactersCharacterIdAssetsLocationsPostInnerPosition) Get() *CharactersCharacterIdAssetsLocationsPostInnerPosition {
	return v.value
}

func (v *NullableCharactersCharacterIdAssetsLocationsPostInnerPosition) Set(val *CharactersCharacterIdAssetsLocationsPostInnerPosition) {
	v.value = val
	v.isSet = true
}

func (v NullableCharactersCharacterIdAssetsLocationsPostInnerPosition) IsSet() bool {
	return v.isSet
}

func (v *NullableCharactersCharacterIdAssetsLocationsPostInnerPosition) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCharactersCharacterIdAssetsLocationsPostInnerPosition(val *CharactersCharacterIdAssetsLocationsPostInnerPosition) *NullableCharactersCharacterIdAssetsLocationsPostInnerPosition {
	return &NullableCharactersCharacterIdAssetsLocationsPostInnerPosition{value: val, isSet: true}
}

func (v NullableCharactersCharacterIdAssetsLocationsPostInnerPosition) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCharactersCharacterIdAssetsLocationsPostInnerPosition) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


