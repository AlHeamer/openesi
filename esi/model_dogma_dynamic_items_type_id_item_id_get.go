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

// checks if the DogmaDynamicItemsTypeIdItemIdGet type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &DogmaDynamicItemsTypeIdItemIdGet{}

// DogmaDynamicItemsTypeIdItemIdGet struct for DogmaDynamicItemsTypeIdItemIdGet
type DogmaDynamicItemsTypeIdItemIdGet struct {
	// The ID of the character who created the item
	CreatedBy int64 `json:"created_by"`
	DogmaAttributes []DogmaDynamicItemsTypeIdItemIdGetDogmaAttributesInner `json:"dogma_attributes"`
	DogmaEffects []DogmaDynamicItemsTypeIdItemIdGetDogmaEffectsInner `json:"dogma_effects"`
	// The type ID of the mutator used to generate the dynamic item.
	MutatorTypeId int64 `json:"mutator_type_id"`
	// The type ID of the source item the mutator was applied to create the dynamic item.
	SourceTypeId int64 `json:"source_type_id"`
}

type _DogmaDynamicItemsTypeIdItemIdGet DogmaDynamicItemsTypeIdItemIdGet

// NewDogmaDynamicItemsTypeIdItemIdGet instantiates a new DogmaDynamicItemsTypeIdItemIdGet object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDogmaDynamicItemsTypeIdItemIdGet(createdBy int64, dogmaAttributes []DogmaDynamicItemsTypeIdItemIdGetDogmaAttributesInner, dogmaEffects []DogmaDynamicItemsTypeIdItemIdGetDogmaEffectsInner, mutatorTypeId int64, sourceTypeId int64) *DogmaDynamicItemsTypeIdItemIdGet {
	this := DogmaDynamicItemsTypeIdItemIdGet{}
	this.CreatedBy = createdBy
	this.DogmaAttributes = dogmaAttributes
	this.DogmaEffects = dogmaEffects
	this.MutatorTypeId = mutatorTypeId
	this.SourceTypeId = sourceTypeId
	return &this
}

// NewDogmaDynamicItemsTypeIdItemIdGetWithDefaults instantiates a new DogmaDynamicItemsTypeIdItemIdGet object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDogmaDynamicItemsTypeIdItemIdGetWithDefaults() *DogmaDynamicItemsTypeIdItemIdGet {
	this := DogmaDynamicItemsTypeIdItemIdGet{}
	return &this
}

// GetCreatedBy returns the CreatedBy field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetCreatedBy() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.CreatedBy
}

// GetCreatedByOk returns a tuple with the CreatedBy field value
// and a boolean to check if the value has been set.
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetCreatedByOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CreatedBy, true
}

// SetCreatedBy sets field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) SetCreatedBy(v int64) {
	o.CreatedBy = v
}

// GetDogmaAttributes returns the DogmaAttributes field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetDogmaAttributes() []DogmaDynamicItemsTypeIdItemIdGetDogmaAttributesInner {
	if o == nil {
		var ret []DogmaDynamicItemsTypeIdItemIdGetDogmaAttributesInner
		return ret
	}

	return o.DogmaAttributes
}

// GetDogmaAttributesOk returns a tuple with the DogmaAttributes field value
// and a boolean to check if the value has been set.
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetDogmaAttributesOk() ([]DogmaDynamicItemsTypeIdItemIdGetDogmaAttributesInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.DogmaAttributes, true
}

// SetDogmaAttributes sets field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) SetDogmaAttributes(v []DogmaDynamicItemsTypeIdItemIdGetDogmaAttributesInner) {
	o.DogmaAttributes = v
}

// GetDogmaEffects returns the DogmaEffects field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetDogmaEffects() []DogmaDynamicItemsTypeIdItemIdGetDogmaEffectsInner {
	if o == nil {
		var ret []DogmaDynamicItemsTypeIdItemIdGetDogmaEffectsInner
		return ret
	}

	return o.DogmaEffects
}

// GetDogmaEffectsOk returns a tuple with the DogmaEffects field value
// and a boolean to check if the value has been set.
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetDogmaEffectsOk() ([]DogmaDynamicItemsTypeIdItemIdGetDogmaEffectsInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.DogmaEffects, true
}

// SetDogmaEffects sets field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) SetDogmaEffects(v []DogmaDynamicItemsTypeIdItemIdGetDogmaEffectsInner) {
	o.DogmaEffects = v
}

// GetMutatorTypeId returns the MutatorTypeId field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetMutatorTypeId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.MutatorTypeId
}

// GetMutatorTypeIdOk returns a tuple with the MutatorTypeId field value
// and a boolean to check if the value has been set.
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetMutatorTypeIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.MutatorTypeId, true
}

// SetMutatorTypeId sets field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) SetMutatorTypeId(v int64) {
	o.MutatorTypeId = v
}

// GetSourceTypeId returns the SourceTypeId field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetSourceTypeId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.SourceTypeId
}

// GetSourceTypeIdOk returns a tuple with the SourceTypeId field value
// and a boolean to check if the value has been set.
func (o *DogmaDynamicItemsTypeIdItemIdGet) GetSourceTypeIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SourceTypeId, true
}

// SetSourceTypeId sets field value
func (o *DogmaDynamicItemsTypeIdItemIdGet) SetSourceTypeId(v int64) {
	o.SourceTypeId = v
}

func (o DogmaDynamicItemsTypeIdItemIdGet) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o DogmaDynamicItemsTypeIdItemIdGet) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["created_by"] = o.CreatedBy
	toSerialize["dogma_attributes"] = o.DogmaAttributes
	toSerialize["dogma_effects"] = o.DogmaEffects
	toSerialize["mutator_type_id"] = o.MutatorTypeId
	toSerialize["source_type_id"] = o.SourceTypeId
	return toSerialize, nil
}

func (o *DogmaDynamicItemsTypeIdItemIdGet) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"created_by",
		"dogma_attributes",
		"dogma_effects",
		"mutator_type_id",
		"source_type_id",
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

	varDogmaDynamicItemsTypeIdItemIdGet := _DogmaDynamicItemsTypeIdItemIdGet{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varDogmaDynamicItemsTypeIdItemIdGet)

	if err != nil {
		return err
	}

	*o = DogmaDynamicItemsTypeIdItemIdGet(varDogmaDynamicItemsTypeIdItemIdGet)

	return err
}

type NullableDogmaDynamicItemsTypeIdItemIdGet struct {
	value *DogmaDynamicItemsTypeIdItemIdGet
	isSet bool
}

func (v NullableDogmaDynamicItemsTypeIdItemIdGet) Get() *DogmaDynamicItemsTypeIdItemIdGet {
	return v.value
}

func (v *NullableDogmaDynamicItemsTypeIdItemIdGet) Set(val *DogmaDynamicItemsTypeIdItemIdGet) {
	v.value = val
	v.isSet = true
}

func (v NullableDogmaDynamicItemsTypeIdItemIdGet) IsSet() bool {
	return v.isSet
}

func (v *NullableDogmaDynamicItemsTypeIdItemIdGet) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDogmaDynamicItemsTypeIdItemIdGet(val *DogmaDynamicItemsTypeIdItemIdGet) *NullableDogmaDynamicItemsTypeIdItemIdGet {
	return &NullableDogmaDynamicItemsTypeIdItemIdGet{value: val, isSet: true}
}

func (v NullableDogmaDynamicItemsTypeIdItemIdGet) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDogmaDynamicItemsTypeIdItemIdGet) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


