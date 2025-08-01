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

// checks if the KillmailsKillmailIdKillmailHashGet type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &KillmailsKillmailIdKillmailHashGet{}

// KillmailsKillmailIdKillmailHashGet struct for KillmailsKillmailIdKillmailHashGet
type KillmailsKillmailIdKillmailHashGet struct {
	Attackers []KillmailsKillmailIdKillmailHashGetAttackersInner `json:"attackers"`
	// ID of the killmail
	KillmailId int64 `json:"killmail_id"`
	// Time that the victim was killed and the killmail generated 
	KillmailTime time.Time `json:"killmail_time"`
	// Moon if the kill took place at one
	MoonId *int64 `json:"moon_id,omitempty"`
	// Solar system that the kill took place in 
	SolarSystemId int64 `json:"solar_system_id"`
	Victim KillmailsKillmailIdKillmailHashGetVictim `json:"victim"`
	// War if the killmail is generated in relation to an official war 
	WarId *int64 `json:"war_id,omitempty"`
}

type _KillmailsKillmailIdKillmailHashGet KillmailsKillmailIdKillmailHashGet

// NewKillmailsKillmailIdKillmailHashGet instantiates a new KillmailsKillmailIdKillmailHashGet object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewKillmailsKillmailIdKillmailHashGet(attackers []KillmailsKillmailIdKillmailHashGetAttackersInner, killmailId int64, killmailTime time.Time, solarSystemId int64, victim KillmailsKillmailIdKillmailHashGetVictim) *KillmailsKillmailIdKillmailHashGet {
	this := KillmailsKillmailIdKillmailHashGet{}
	this.Attackers = attackers
	this.KillmailId = killmailId
	this.KillmailTime = killmailTime
	this.SolarSystemId = solarSystemId
	this.Victim = victim
	return &this
}

// NewKillmailsKillmailIdKillmailHashGetWithDefaults instantiates a new KillmailsKillmailIdKillmailHashGet object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewKillmailsKillmailIdKillmailHashGetWithDefaults() *KillmailsKillmailIdKillmailHashGet {
	this := KillmailsKillmailIdKillmailHashGet{}
	return &this
}

// GetAttackers returns the Attackers field value
func (o *KillmailsKillmailIdKillmailHashGet) GetAttackers() []KillmailsKillmailIdKillmailHashGetAttackersInner {
	if o == nil {
		var ret []KillmailsKillmailIdKillmailHashGetAttackersInner
		return ret
	}

	return o.Attackers
}

// GetAttackersOk returns a tuple with the Attackers field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGet) GetAttackersOk() ([]KillmailsKillmailIdKillmailHashGetAttackersInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.Attackers, true
}

// SetAttackers sets field value
func (o *KillmailsKillmailIdKillmailHashGet) SetAttackers(v []KillmailsKillmailIdKillmailHashGetAttackersInner) {
	o.Attackers = v
}

// GetKillmailId returns the KillmailId field value
func (o *KillmailsKillmailIdKillmailHashGet) GetKillmailId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.KillmailId
}

// GetKillmailIdOk returns a tuple with the KillmailId field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGet) GetKillmailIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.KillmailId, true
}

// SetKillmailId sets field value
func (o *KillmailsKillmailIdKillmailHashGet) SetKillmailId(v int64) {
	o.KillmailId = v
}

// GetKillmailTime returns the KillmailTime field value
func (o *KillmailsKillmailIdKillmailHashGet) GetKillmailTime() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.KillmailTime
}

// GetKillmailTimeOk returns a tuple with the KillmailTime field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGet) GetKillmailTimeOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.KillmailTime, true
}

// SetKillmailTime sets field value
func (o *KillmailsKillmailIdKillmailHashGet) SetKillmailTime(v time.Time) {
	o.KillmailTime = v
}

// GetMoonId returns the MoonId field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGet) GetMoonId() int64 {
	if o == nil || IsNil(o.MoonId) {
		var ret int64
		return ret
	}
	return *o.MoonId
}

// GetMoonIdOk returns a tuple with the MoonId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGet) GetMoonIdOk() (*int64, bool) {
	if o == nil || IsNil(o.MoonId) {
		return nil, false
	}
	return o.MoonId, true
}

// HasMoonId returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGet) HasMoonId() bool {
	if o != nil && !IsNil(o.MoonId) {
		return true
	}

	return false
}

// SetMoonId gets a reference to the given int64 and assigns it to the MoonId field.
func (o *KillmailsKillmailIdKillmailHashGet) SetMoonId(v int64) {
	o.MoonId = &v
}

// GetSolarSystemId returns the SolarSystemId field value
func (o *KillmailsKillmailIdKillmailHashGet) GetSolarSystemId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.SolarSystemId
}

// GetSolarSystemIdOk returns a tuple with the SolarSystemId field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGet) GetSolarSystemIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SolarSystemId, true
}

// SetSolarSystemId sets field value
func (o *KillmailsKillmailIdKillmailHashGet) SetSolarSystemId(v int64) {
	o.SolarSystemId = v
}

// GetVictim returns the Victim field value
func (o *KillmailsKillmailIdKillmailHashGet) GetVictim() KillmailsKillmailIdKillmailHashGetVictim {
	if o == nil {
		var ret KillmailsKillmailIdKillmailHashGetVictim
		return ret
	}

	return o.Victim
}

// GetVictimOk returns a tuple with the Victim field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGet) GetVictimOk() (*KillmailsKillmailIdKillmailHashGetVictim, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Victim, true
}

// SetVictim sets field value
func (o *KillmailsKillmailIdKillmailHashGet) SetVictim(v KillmailsKillmailIdKillmailHashGetVictim) {
	o.Victim = v
}

// GetWarId returns the WarId field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGet) GetWarId() int64 {
	if o == nil || IsNil(o.WarId) {
		var ret int64
		return ret
	}
	return *o.WarId
}

// GetWarIdOk returns a tuple with the WarId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGet) GetWarIdOk() (*int64, bool) {
	if o == nil || IsNil(o.WarId) {
		return nil, false
	}
	return o.WarId, true
}

// HasWarId returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGet) HasWarId() bool {
	if o != nil && !IsNil(o.WarId) {
		return true
	}

	return false
}

// SetWarId gets a reference to the given int64 and assigns it to the WarId field.
func (o *KillmailsKillmailIdKillmailHashGet) SetWarId(v int64) {
	o.WarId = &v
}

func (o KillmailsKillmailIdKillmailHashGet) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o KillmailsKillmailIdKillmailHashGet) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["attackers"] = o.Attackers
	toSerialize["killmail_id"] = o.KillmailId
	toSerialize["killmail_time"] = o.KillmailTime
	if !IsNil(o.MoonId) {
		toSerialize["moon_id"] = o.MoonId
	}
	toSerialize["solar_system_id"] = o.SolarSystemId
	toSerialize["victim"] = o.Victim
	if !IsNil(o.WarId) {
		toSerialize["war_id"] = o.WarId
	}
	return toSerialize, nil
}

func (o *KillmailsKillmailIdKillmailHashGet) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"attackers",
		"killmail_id",
		"killmail_time",
		"solar_system_id",
		"victim",
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

	varKillmailsKillmailIdKillmailHashGet := _KillmailsKillmailIdKillmailHashGet{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varKillmailsKillmailIdKillmailHashGet)

	if err != nil {
		return err
	}

	*o = KillmailsKillmailIdKillmailHashGet(varKillmailsKillmailIdKillmailHashGet)

	return err
}

type NullableKillmailsKillmailIdKillmailHashGet struct {
	value *KillmailsKillmailIdKillmailHashGet
	isSet bool
}

func (v NullableKillmailsKillmailIdKillmailHashGet) Get() *KillmailsKillmailIdKillmailHashGet {
	return v.value
}

func (v *NullableKillmailsKillmailIdKillmailHashGet) Set(val *KillmailsKillmailIdKillmailHashGet) {
	v.value = val
	v.isSet = true
}

func (v NullableKillmailsKillmailIdKillmailHashGet) IsSet() bool {
	return v.isSet
}

func (v *NullableKillmailsKillmailIdKillmailHashGet) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKillmailsKillmailIdKillmailHashGet(val *KillmailsKillmailIdKillmailHashGet) *NullableKillmailsKillmailIdKillmailHashGet {
	return &NullableKillmailsKillmailIdKillmailHashGet{value: val, isSet: true}
}

func (v NullableKillmailsKillmailIdKillmailHashGet) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKillmailsKillmailIdKillmailHashGet) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


