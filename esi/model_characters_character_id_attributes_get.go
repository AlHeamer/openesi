/*
EVE Stellar Information (ESI) - tranquility

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2020-01-01
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package esi

import (
	"encoding/json"
	"time"
	"bytes"
	"fmt"
)

// checks if the CharactersCharacterIdAttributesGet type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CharactersCharacterIdAttributesGet{}

// CharactersCharacterIdAttributesGet struct for CharactersCharacterIdAttributesGet
type CharactersCharacterIdAttributesGet struct {
	// Neural remapping cooldown after a character uses remap accrued over time
	AccruedRemapCooldownDate *time.Time `json:"accrued_remap_cooldown_date,omitempty"`
	// Number of available bonus character neural remaps
	BonusRemaps *int64 `json:"bonus_remaps,omitempty"`
	Charisma int64 `json:"charisma"`
	Intelligence int64 `json:"intelligence"`
	// Datetime of last neural remap, including usage of bonus remaps
	LastRemapDate *time.Time `json:"last_remap_date,omitempty"`
	Memory int64 `json:"memory"`
	Perception int64 `json:"perception"`
	Willpower int64 `json:"willpower"`
}

type _CharactersCharacterIdAttributesGet CharactersCharacterIdAttributesGet

// NewCharactersCharacterIdAttributesGet instantiates a new CharactersCharacterIdAttributesGet object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCharactersCharacterIdAttributesGet(charisma int64, intelligence int64, memory int64, perception int64, willpower int64) *CharactersCharacterIdAttributesGet {
	this := CharactersCharacterIdAttributesGet{}
	this.Charisma = charisma
	this.Intelligence = intelligence
	this.Memory = memory
	this.Perception = perception
	this.Willpower = willpower
	return &this
}

// NewCharactersCharacterIdAttributesGetWithDefaults instantiates a new CharactersCharacterIdAttributesGet object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCharactersCharacterIdAttributesGetWithDefaults() *CharactersCharacterIdAttributesGet {
	this := CharactersCharacterIdAttributesGet{}
	return &this
}

// GetAccruedRemapCooldownDate returns the AccruedRemapCooldownDate field value if set, zero value otherwise.
func (o *CharactersCharacterIdAttributesGet) GetAccruedRemapCooldownDate() time.Time {
	if o == nil || IsNil(o.AccruedRemapCooldownDate) {
		var ret time.Time
		return ret
	}
	return *o.AccruedRemapCooldownDate
}

// GetAccruedRemapCooldownDateOk returns a tuple with the AccruedRemapCooldownDate field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAttributesGet) GetAccruedRemapCooldownDateOk() (*time.Time, bool) {
	if o == nil || IsNil(o.AccruedRemapCooldownDate) {
		return nil, false
	}
	return o.AccruedRemapCooldownDate, true
}

// HasAccruedRemapCooldownDate returns a boolean if a field has been set.
func (o *CharactersCharacterIdAttributesGet) HasAccruedRemapCooldownDate() bool {
	if o != nil && !IsNil(o.AccruedRemapCooldownDate) {
		return true
	}

	return false
}

// SetAccruedRemapCooldownDate gets a reference to the given time.Time and assigns it to the AccruedRemapCooldownDate field.
func (o *CharactersCharacterIdAttributesGet) SetAccruedRemapCooldownDate(v time.Time) {
	o.AccruedRemapCooldownDate = &v
}

// GetBonusRemaps returns the BonusRemaps field value if set, zero value otherwise.
func (o *CharactersCharacterIdAttributesGet) GetBonusRemaps() int64 {
	if o == nil || IsNil(o.BonusRemaps) {
		var ret int64
		return ret
	}
	return *o.BonusRemaps
}

// GetBonusRemapsOk returns a tuple with the BonusRemaps field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAttributesGet) GetBonusRemapsOk() (*int64, bool) {
	if o == nil || IsNil(o.BonusRemaps) {
		return nil, false
	}
	return o.BonusRemaps, true
}

// HasBonusRemaps returns a boolean if a field has been set.
func (o *CharactersCharacterIdAttributesGet) HasBonusRemaps() bool {
	if o != nil && !IsNil(o.BonusRemaps) {
		return true
	}

	return false
}

// SetBonusRemaps gets a reference to the given int64 and assigns it to the BonusRemaps field.
func (o *CharactersCharacterIdAttributesGet) SetBonusRemaps(v int64) {
	o.BonusRemaps = &v
}

// GetCharisma returns the Charisma field value
func (o *CharactersCharacterIdAttributesGet) GetCharisma() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Charisma
}

// GetCharismaOk returns a tuple with the Charisma field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAttributesGet) GetCharismaOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Charisma, true
}

// SetCharisma sets field value
func (o *CharactersCharacterIdAttributesGet) SetCharisma(v int64) {
	o.Charisma = v
}

// GetIntelligence returns the Intelligence field value
func (o *CharactersCharacterIdAttributesGet) GetIntelligence() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Intelligence
}

// GetIntelligenceOk returns a tuple with the Intelligence field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAttributesGet) GetIntelligenceOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Intelligence, true
}

// SetIntelligence sets field value
func (o *CharactersCharacterIdAttributesGet) SetIntelligence(v int64) {
	o.Intelligence = v
}

// GetLastRemapDate returns the LastRemapDate field value if set, zero value otherwise.
func (o *CharactersCharacterIdAttributesGet) GetLastRemapDate() time.Time {
	if o == nil || IsNil(o.LastRemapDate) {
		var ret time.Time
		return ret
	}
	return *o.LastRemapDate
}

// GetLastRemapDateOk returns a tuple with the LastRemapDate field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAttributesGet) GetLastRemapDateOk() (*time.Time, bool) {
	if o == nil || IsNil(o.LastRemapDate) {
		return nil, false
	}
	return o.LastRemapDate, true
}

// HasLastRemapDate returns a boolean if a field has been set.
func (o *CharactersCharacterIdAttributesGet) HasLastRemapDate() bool {
	if o != nil && !IsNil(o.LastRemapDate) {
		return true
	}

	return false
}

// SetLastRemapDate gets a reference to the given time.Time and assigns it to the LastRemapDate field.
func (o *CharactersCharacterIdAttributesGet) SetLastRemapDate(v time.Time) {
	o.LastRemapDate = &v
}

// GetMemory returns the Memory field value
func (o *CharactersCharacterIdAttributesGet) GetMemory() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Memory
}

// GetMemoryOk returns a tuple with the Memory field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAttributesGet) GetMemoryOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Memory, true
}

// SetMemory sets field value
func (o *CharactersCharacterIdAttributesGet) SetMemory(v int64) {
	o.Memory = v
}

// GetPerception returns the Perception field value
func (o *CharactersCharacterIdAttributesGet) GetPerception() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Perception
}

// GetPerceptionOk returns a tuple with the Perception field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAttributesGet) GetPerceptionOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Perception, true
}

// SetPerception sets field value
func (o *CharactersCharacterIdAttributesGet) SetPerception(v int64) {
	o.Perception = v
}

// GetWillpower returns the Willpower field value
func (o *CharactersCharacterIdAttributesGet) GetWillpower() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Willpower
}

// GetWillpowerOk returns a tuple with the Willpower field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdAttributesGet) GetWillpowerOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Willpower, true
}

// SetWillpower sets field value
func (o *CharactersCharacterIdAttributesGet) SetWillpower(v int64) {
	o.Willpower = v
}

func (o CharactersCharacterIdAttributesGet) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CharactersCharacterIdAttributesGet) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.AccruedRemapCooldownDate) {
		toSerialize["accrued_remap_cooldown_date"] = o.AccruedRemapCooldownDate
	}
	if !IsNil(o.BonusRemaps) {
		toSerialize["bonus_remaps"] = o.BonusRemaps
	}
	toSerialize["charisma"] = o.Charisma
	toSerialize["intelligence"] = o.Intelligence
	if !IsNil(o.LastRemapDate) {
		toSerialize["last_remap_date"] = o.LastRemapDate
	}
	toSerialize["memory"] = o.Memory
	toSerialize["perception"] = o.Perception
	toSerialize["willpower"] = o.Willpower
	return toSerialize, nil
}

func (o *CharactersCharacterIdAttributesGet) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"charisma",
		"intelligence",
		"memory",
		"perception",
		"willpower",
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

	varCharactersCharacterIdAttributesGet := _CharactersCharacterIdAttributesGet{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCharactersCharacterIdAttributesGet)

	if err != nil {
		return err
	}

	*o = CharactersCharacterIdAttributesGet(varCharactersCharacterIdAttributesGet)

	return err
}

type NullableCharactersCharacterIdAttributesGet struct {
	value *CharactersCharacterIdAttributesGet
	isSet bool
}

func (v NullableCharactersCharacterIdAttributesGet) Get() *CharactersCharacterIdAttributesGet {
	return v.value
}

func (v *NullableCharactersCharacterIdAttributesGet) Set(val *CharactersCharacterIdAttributesGet) {
	v.value = val
	v.isSet = true
}

func (v NullableCharactersCharacterIdAttributesGet) IsSet() bool {
	return v.isSet
}

func (v *NullableCharactersCharacterIdAttributesGet) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCharactersCharacterIdAttributesGet(val *CharactersCharacterIdAttributesGet) *NullableCharactersCharacterIdAttributesGet {
	return &NullableCharactersCharacterIdAttributesGet{value: val, isSet: true}
}

func (v NullableCharactersCharacterIdAttributesGet) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCharactersCharacterIdAttributesGet) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


