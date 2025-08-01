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

// checks if the KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner{}

// KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner item object
type KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner struct {
	Flag int64 `json:"flag"`
	ItemTypeId int64 `json:"item_type_id"`
	QuantityDestroyed *int64 `json:"quantity_destroyed,omitempty"`
	QuantityDropped *int64 `json:"quantity_dropped,omitempty"`
	Singleton int64 `json:"singleton"`
}

type _KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner

// NewKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner instantiates a new KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner(flag int64, itemTypeId int64, singleton int64) *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner {
	this := KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner{}
	this.Flag = flag
	this.ItemTypeId = itemTypeId
	this.Singleton = singleton
	return &this
}

// NewKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInnerWithDefaults instantiates a new KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInnerWithDefaults() *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner {
	this := KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner{}
	return &this
}

// GetFlag returns the Flag field value
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetFlag() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Flag
}

// GetFlagOk returns a tuple with the Flag field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetFlagOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Flag, true
}

// SetFlag sets field value
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) SetFlag(v int64) {
	o.Flag = v
}

// GetItemTypeId returns the ItemTypeId field value
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetItemTypeId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.ItemTypeId
}

// GetItemTypeIdOk returns a tuple with the ItemTypeId field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetItemTypeIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ItemTypeId, true
}

// SetItemTypeId sets field value
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) SetItemTypeId(v int64) {
	o.ItemTypeId = v
}

// GetQuantityDestroyed returns the QuantityDestroyed field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetQuantityDestroyed() int64 {
	if o == nil || IsNil(o.QuantityDestroyed) {
		var ret int64
		return ret
	}
	return *o.QuantityDestroyed
}

// GetQuantityDestroyedOk returns a tuple with the QuantityDestroyed field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetQuantityDestroyedOk() (*int64, bool) {
	if o == nil || IsNil(o.QuantityDestroyed) {
		return nil, false
	}
	return o.QuantityDestroyed, true
}

// HasQuantityDestroyed returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) HasQuantityDestroyed() bool {
	if o != nil && !IsNil(o.QuantityDestroyed) {
		return true
	}

	return false
}

// SetQuantityDestroyed gets a reference to the given int64 and assigns it to the QuantityDestroyed field.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) SetQuantityDestroyed(v int64) {
	o.QuantityDestroyed = &v
}

// GetQuantityDropped returns the QuantityDropped field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetQuantityDropped() int64 {
	if o == nil || IsNil(o.QuantityDropped) {
		var ret int64
		return ret
	}
	return *o.QuantityDropped
}

// GetQuantityDroppedOk returns a tuple with the QuantityDropped field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetQuantityDroppedOk() (*int64, bool) {
	if o == nil || IsNil(o.QuantityDropped) {
		return nil, false
	}
	return o.QuantityDropped, true
}

// HasQuantityDropped returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) HasQuantityDropped() bool {
	if o != nil && !IsNil(o.QuantityDropped) {
		return true
	}

	return false
}

// SetQuantityDropped gets a reference to the given int64 and assigns it to the QuantityDropped field.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) SetQuantityDropped(v int64) {
	o.QuantityDropped = &v
}

// GetSingleton returns the Singleton field value
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetSingleton() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Singleton
}

// GetSingletonOk returns a tuple with the Singleton field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) GetSingletonOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Singleton, true
}

// SetSingleton sets field value
func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) SetSingleton(v int64) {
	o.Singleton = v
}

func (o KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["flag"] = o.Flag
	toSerialize["item_type_id"] = o.ItemTypeId
	if !IsNil(o.QuantityDestroyed) {
		toSerialize["quantity_destroyed"] = o.QuantityDestroyed
	}
	if !IsNil(o.QuantityDropped) {
		toSerialize["quantity_dropped"] = o.QuantityDropped
	}
	toSerialize["singleton"] = o.Singleton
	return toSerialize, nil
}

func (o *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"flag",
		"item_type_id",
		"singleton",
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

	varKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner := _KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner)

	if err != nil {
		return err
	}

	*o = KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner(varKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner)

	return err
}

type NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner struct {
	value *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner
	isSet bool
}

func (v NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) Get() *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner {
	return v.value
}

func (v *NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) Set(val *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) {
	v.value = val
	v.isSet = true
}

func (v NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) IsSet() bool {
	return v.isSet
}

func (v *NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner(val *KillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) *NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner {
	return &NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner{value: val, isSet: true}
}

func (v NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKillmailsKillmailIdKillmailHashGetVictimItemsInnerItemsInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


