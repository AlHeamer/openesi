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

// checks if the CharactersCharacterIdLocationGet type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CharactersCharacterIdLocationGet{}

// CharactersCharacterIdLocationGet struct for CharactersCharacterIdLocationGet
type CharactersCharacterIdLocationGet struct {
	SolarSystemId int64 `json:"solar_system_id"`
	StationId *int64 `json:"station_id,omitempty"`
	StructureId *int64 `json:"structure_id,omitempty"`
}

type _CharactersCharacterIdLocationGet CharactersCharacterIdLocationGet

// NewCharactersCharacterIdLocationGet instantiates a new CharactersCharacterIdLocationGet object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCharactersCharacterIdLocationGet(solarSystemId int64) *CharactersCharacterIdLocationGet {
	this := CharactersCharacterIdLocationGet{}
	this.SolarSystemId = solarSystemId
	return &this
}

// NewCharactersCharacterIdLocationGetWithDefaults instantiates a new CharactersCharacterIdLocationGet object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCharactersCharacterIdLocationGetWithDefaults() *CharactersCharacterIdLocationGet {
	this := CharactersCharacterIdLocationGet{}
	return &this
}

// GetSolarSystemId returns the SolarSystemId field value
func (o *CharactersCharacterIdLocationGet) GetSolarSystemId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.SolarSystemId
}

// GetSolarSystemIdOk returns a tuple with the SolarSystemId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdLocationGet) GetSolarSystemIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SolarSystemId, true
}

// SetSolarSystemId sets field value
func (o *CharactersCharacterIdLocationGet) SetSolarSystemId(v int64) {
	o.SolarSystemId = v
}

// GetStationId returns the StationId field value if set, zero value otherwise.
func (o *CharactersCharacterIdLocationGet) GetStationId() int64 {
	if o == nil || IsNil(o.StationId) {
		var ret int64
		return ret
	}
	return *o.StationId
}

// GetStationIdOk returns a tuple with the StationId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdLocationGet) GetStationIdOk() (*int64, bool) {
	if o == nil || IsNil(o.StationId) {
		return nil, false
	}
	return o.StationId, true
}

// HasStationId returns a boolean if a field has been set.
func (o *CharactersCharacterIdLocationGet) HasStationId() bool {
	if o != nil && !IsNil(o.StationId) {
		return true
	}

	return false
}

// SetStationId gets a reference to the given int64 and assigns it to the StationId field.
func (o *CharactersCharacterIdLocationGet) SetStationId(v int64) {
	o.StationId = &v
}

// GetStructureId returns the StructureId field value if set, zero value otherwise.
func (o *CharactersCharacterIdLocationGet) GetStructureId() int64 {
	if o == nil || IsNil(o.StructureId) {
		var ret int64
		return ret
	}
	return *o.StructureId
}

// GetStructureIdOk returns a tuple with the StructureId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdLocationGet) GetStructureIdOk() (*int64, bool) {
	if o == nil || IsNil(o.StructureId) {
		return nil, false
	}
	return o.StructureId, true
}

// HasStructureId returns a boolean if a field has been set.
func (o *CharactersCharacterIdLocationGet) HasStructureId() bool {
	if o != nil && !IsNil(o.StructureId) {
		return true
	}

	return false
}

// SetStructureId gets a reference to the given int64 and assigns it to the StructureId field.
func (o *CharactersCharacterIdLocationGet) SetStructureId(v int64) {
	o.StructureId = &v
}

func (o CharactersCharacterIdLocationGet) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CharactersCharacterIdLocationGet) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["solar_system_id"] = o.SolarSystemId
	if !IsNil(o.StationId) {
		toSerialize["station_id"] = o.StationId
	}
	if !IsNil(o.StructureId) {
		toSerialize["structure_id"] = o.StructureId
	}
	return toSerialize, nil
}

func (o *CharactersCharacterIdLocationGet) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"solar_system_id",
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

	varCharactersCharacterIdLocationGet := _CharactersCharacterIdLocationGet{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCharactersCharacterIdLocationGet)

	if err != nil {
		return err
	}

	*o = CharactersCharacterIdLocationGet(varCharactersCharacterIdLocationGet)

	return err
}

type NullableCharactersCharacterIdLocationGet struct {
	value *CharactersCharacterIdLocationGet
	isSet bool
}

func (v NullableCharactersCharacterIdLocationGet) Get() *CharactersCharacterIdLocationGet {
	return v.value
}

func (v *NullableCharactersCharacterIdLocationGet) Set(val *CharactersCharacterIdLocationGet) {
	v.value = val
	v.isSet = true
}

func (v NullableCharactersCharacterIdLocationGet) IsSet() bool {
	return v.isSet
}

func (v *NullableCharactersCharacterIdLocationGet) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCharactersCharacterIdLocationGet(val *CharactersCharacterIdLocationGet) *NullableCharactersCharacterIdLocationGet {
	return &NullableCharactersCharacterIdLocationGet{value: val, isSet: true}
}

func (v NullableCharactersCharacterIdLocationGet) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCharactersCharacterIdLocationGet) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


