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

// checks if the UniverseStructuresStructureIdGetPosition type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UniverseStructuresStructureIdGetPosition{}

// UniverseStructuresStructureIdGetPosition Coordinates of the structure in Cartesian space relative to the Sun, in metres. 
type UniverseStructuresStructureIdGetPosition struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	Z float64 `json:"z"`
}

type _UniverseStructuresStructureIdGetPosition UniverseStructuresStructureIdGetPosition

// NewUniverseStructuresStructureIdGetPosition instantiates a new UniverseStructuresStructureIdGetPosition object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUniverseStructuresStructureIdGetPosition(x float64, y float64, z float64) *UniverseStructuresStructureIdGetPosition {
	this := UniverseStructuresStructureIdGetPosition{}
	this.X = x
	this.Y = y
	this.Z = z
	return &this
}

// NewUniverseStructuresStructureIdGetPositionWithDefaults instantiates a new UniverseStructuresStructureIdGetPosition object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUniverseStructuresStructureIdGetPositionWithDefaults() *UniverseStructuresStructureIdGetPosition {
	this := UniverseStructuresStructureIdGetPosition{}
	return &this
}

// GetX returns the X field value
func (o *UniverseStructuresStructureIdGetPosition) GetX() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.X
}

// GetXOk returns a tuple with the X field value
// and a boolean to check if the value has been set.
func (o *UniverseStructuresStructureIdGetPosition) GetXOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.X, true
}

// SetX sets field value
func (o *UniverseStructuresStructureIdGetPosition) SetX(v float64) {
	o.X = v
}

// GetY returns the Y field value
func (o *UniverseStructuresStructureIdGetPosition) GetY() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.Y
}

// GetYOk returns a tuple with the Y field value
// and a boolean to check if the value has been set.
func (o *UniverseStructuresStructureIdGetPosition) GetYOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Y, true
}

// SetY sets field value
func (o *UniverseStructuresStructureIdGetPosition) SetY(v float64) {
	o.Y = v
}

// GetZ returns the Z field value
func (o *UniverseStructuresStructureIdGetPosition) GetZ() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.Z
}

// GetZOk returns a tuple with the Z field value
// and a boolean to check if the value has been set.
func (o *UniverseStructuresStructureIdGetPosition) GetZOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Z, true
}

// SetZ sets field value
func (o *UniverseStructuresStructureIdGetPosition) SetZ(v float64) {
	o.Z = v
}

func (o UniverseStructuresStructureIdGetPosition) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UniverseStructuresStructureIdGetPosition) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["x"] = o.X
	toSerialize["y"] = o.Y
	toSerialize["z"] = o.Z
	return toSerialize, nil
}

func (o *UniverseStructuresStructureIdGetPosition) UnmarshalJSON(data []byte) (err error) {
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

	varUniverseStructuresStructureIdGetPosition := _UniverseStructuresStructureIdGetPosition{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varUniverseStructuresStructureIdGetPosition)

	if err != nil {
		return err
	}

	*o = UniverseStructuresStructureIdGetPosition(varUniverseStructuresStructureIdGetPosition)

	return err
}

type NullableUniverseStructuresStructureIdGetPosition struct {
	value *UniverseStructuresStructureIdGetPosition
	isSet bool
}

func (v NullableUniverseStructuresStructureIdGetPosition) Get() *UniverseStructuresStructureIdGetPosition {
	return v.value
}

func (v *NullableUniverseStructuresStructureIdGetPosition) Set(val *UniverseStructuresStructureIdGetPosition) {
	v.value = val
	v.isSet = true
}

func (v NullableUniverseStructuresStructureIdGetPosition) IsSet() bool {
	return v.isSet
}

func (v *NullableUniverseStructuresStructureIdGetPosition) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUniverseStructuresStructureIdGetPosition(val *UniverseStructuresStructureIdGetPosition) *NullableUniverseStructuresStructureIdGetPosition {
	return &NullableUniverseStructuresStructureIdGetPosition{value: val, isSet: true}
}

func (v NullableUniverseStructuresStructureIdGetPosition) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUniverseStructuresStructureIdGetPosition) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


