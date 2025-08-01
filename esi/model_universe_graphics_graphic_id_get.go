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

// checks if the UniverseGraphicsGraphicIdGet type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UniverseGraphicsGraphicIdGet{}

// UniverseGraphicsGraphicIdGet struct for UniverseGraphicsGraphicIdGet
type UniverseGraphicsGraphicIdGet struct {
	CollisionFile *string `json:"collision_file,omitempty"`
	GraphicFile *string `json:"graphic_file,omitempty"`
	GraphicId int64 `json:"graphic_id"`
	IconFolder *string `json:"icon_folder,omitempty"`
	SofDna *string `json:"sof_dna,omitempty"`
	SofFationName *string `json:"sof_fation_name,omitempty"`
	SofHullName *string `json:"sof_hull_name,omitempty"`
	SofRaceName *string `json:"sof_race_name,omitempty"`
}

type _UniverseGraphicsGraphicIdGet UniverseGraphicsGraphicIdGet

// NewUniverseGraphicsGraphicIdGet instantiates a new UniverseGraphicsGraphicIdGet object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUniverseGraphicsGraphicIdGet(graphicId int64) *UniverseGraphicsGraphicIdGet {
	this := UniverseGraphicsGraphicIdGet{}
	this.GraphicId = graphicId
	return &this
}

// NewUniverseGraphicsGraphicIdGetWithDefaults instantiates a new UniverseGraphicsGraphicIdGet object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUniverseGraphicsGraphicIdGetWithDefaults() *UniverseGraphicsGraphicIdGet {
	this := UniverseGraphicsGraphicIdGet{}
	return &this
}

// GetCollisionFile returns the CollisionFile field value if set, zero value otherwise.
func (o *UniverseGraphicsGraphicIdGet) GetCollisionFile() string {
	if o == nil || IsNil(o.CollisionFile) {
		var ret string
		return ret
	}
	return *o.CollisionFile
}

// GetCollisionFileOk returns a tuple with the CollisionFile field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UniverseGraphicsGraphicIdGet) GetCollisionFileOk() (*string, bool) {
	if o == nil || IsNil(o.CollisionFile) {
		return nil, false
	}
	return o.CollisionFile, true
}

// HasCollisionFile returns a boolean if a field has been set.
func (o *UniverseGraphicsGraphicIdGet) HasCollisionFile() bool {
	if o != nil && !IsNil(o.CollisionFile) {
		return true
	}

	return false
}

// SetCollisionFile gets a reference to the given string and assigns it to the CollisionFile field.
func (o *UniverseGraphicsGraphicIdGet) SetCollisionFile(v string) {
	o.CollisionFile = &v
}

// GetGraphicFile returns the GraphicFile field value if set, zero value otherwise.
func (o *UniverseGraphicsGraphicIdGet) GetGraphicFile() string {
	if o == nil || IsNil(o.GraphicFile) {
		var ret string
		return ret
	}
	return *o.GraphicFile
}

// GetGraphicFileOk returns a tuple with the GraphicFile field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UniverseGraphicsGraphicIdGet) GetGraphicFileOk() (*string, bool) {
	if o == nil || IsNil(o.GraphicFile) {
		return nil, false
	}
	return o.GraphicFile, true
}

// HasGraphicFile returns a boolean if a field has been set.
func (o *UniverseGraphicsGraphicIdGet) HasGraphicFile() bool {
	if o != nil && !IsNil(o.GraphicFile) {
		return true
	}

	return false
}

// SetGraphicFile gets a reference to the given string and assigns it to the GraphicFile field.
func (o *UniverseGraphicsGraphicIdGet) SetGraphicFile(v string) {
	o.GraphicFile = &v
}

// GetGraphicId returns the GraphicId field value
func (o *UniverseGraphicsGraphicIdGet) GetGraphicId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.GraphicId
}

// GetGraphicIdOk returns a tuple with the GraphicId field value
// and a boolean to check if the value has been set.
func (o *UniverseGraphicsGraphicIdGet) GetGraphicIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.GraphicId, true
}

// SetGraphicId sets field value
func (o *UniverseGraphicsGraphicIdGet) SetGraphicId(v int64) {
	o.GraphicId = v
}

// GetIconFolder returns the IconFolder field value if set, zero value otherwise.
func (o *UniverseGraphicsGraphicIdGet) GetIconFolder() string {
	if o == nil || IsNil(o.IconFolder) {
		var ret string
		return ret
	}
	return *o.IconFolder
}

// GetIconFolderOk returns a tuple with the IconFolder field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UniverseGraphicsGraphicIdGet) GetIconFolderOk() (*string, bool) {
	if o == nil || IsNil(o.IconFolder) {
		return nil, false
	}
	return o.IconFolder, true
}

// HasIconFolder returns a boolean if a field has been set.
func (o *UniverseGraphicsGraphicIdGet) HasIconFolder() bool {
	if o != nil && !IsNil(o.IconFolder) {
		return true
	}

	return false
}

// SetIconFolder gets a reference to the given string and assigns it to the IconFolder field.
func (o *UniverseGraphicsGraphicIdGet) SetIconFolder(v string) {
	o.IconFolder = &v
}

// GetSofDna returns the SofDna field value if set, zero value otherwise.
func (o *UniverseGraphicsGraphicIdGet) GetSofDna() string {
	if o == nil || IsNil(o.SofDna) {
		var ret string
		return ret
	}
	return *o.SofDna
}

// GetSofDnaOk returns a tuple with the SofDna field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UniverseGraphicsGraphicIdGet) GetSofDnaOk() (*string, bool) {
	if o == nil || IsNil(o.SofDna) {
		return nil, false
	}
	return o.SofDna, true
}

// HasSofDna returns a boolean if a field has been set.
func (o *UniverseGraphicsGraphicIdGet) HasSofDna() bool {
	if o != nil && !IsNil(o.SofDna) {
		return true
	}

	return false
}

// SetSofDna gets a reference to the given string and assigns it to the SofDna field.
func (o *UniverseGraphicsGraphicIdGet) SetSofDna(v string) {
	o.SofDna = &v
}

// GetSofFationName returns the SofFationName field value if set, zero value otherwise.
func (o *UniverseGraphicsGraphicIdGet) GetSofFationName() string {
	if o == nil || IsNil(o.SofFationName) {
		var ret string
		return ret
	}
	return *o.SofFationName
}

// GetSofFationNameOk returns a tuple with the SofFationName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UniverseGraphicsGraphicIdGet) GetSofFationNameOk() (*string, bool) {
	if o == nil || IsNil(o.SofFationName) {
		return nil, false
	}
	return o.SofFationName, true
}

// HasSofFationName returns a boolean if a field has been set.
func (o *UniverseGraphicsGraphicIdGet) HasSofFationName() bool {
	if o != nil && !IsNil(o.SofFationName) {
		return true
	}

	return false
}

// SetSofFationName gets a reference to the given string and assigns it to the SofFationName field.
func (o *UniverseGraphicsGraphicIdGet) SetSofFationName(v string) {
	o.SofFationName = &v
}

// GetSofHullName returns the SofHullName field value if set, zero value otherwise.
func (o *UniverseGraphicsGraphicIdGet) GetSofHullName() string {
	if o == nil || IsNil(o.SofHullName) {
		var ret string
		return ret
	}
	return *o.SofHullName
}

// GetSofHullNameOk returns a tuple with the SofHullName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UniverseGraphicsGraphicIdGet) GetSofHullNameOk() (*string, bool) {
	if o == nil || IsNil(o.SofHullName) {
		return nil, false
	}
	return o.SofHullName, true
}

// HasSofHullName returns a boolean if a field has been set.
func (o *UniverseGraphicsGraphicIdGet) HasSofHullName() bool {
	if o != nil && !IsNil(o.SofHullName) {
		return true
	}

	return false
}

// SetSofHullName gets a reference to the given string and assigns it to the SofHullName field.
func (o *UniverseGraphicsGraphicIdGet) SetSofHullName(v string) {
	o.SofHullName = &v
}

// GetSofRaceName returns the SofRaceName field value if set, zero value otherwise.
func (o *UniverseGraphicsGraphicIdGet) GetSofRaceName() string {
	if o == nil || IsNil(o.SofRaceName) {
		var ret string
		return ret
	}
	return *o.SofRaceName
}

// GetSofRaceNameOk returns a tuple with the SofRaceName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UniverseGraphicsGraphicIdGet) GetSofRaceNameOk() (*string, bool) {
	if o == nil || IsNil(o.SofRaceName) {
		return nil, false
	}
	return o.SofRaceName, true
}

// HasSofRaceName returns a boolean if a field has been set.
func (o *UniverseGraphicsGraphicIdGet) HasSofRaceName() bool {
	if o != nil && !IsNil(o.SofRaceName) {
		return true
	}

	return false
}

// SetSofRaceName gets a reference to the given string and assigns it to the SofRaceName field.
func (o *UniverseGraphicsGraphicIdGet) SetSofRaceName(v string) {
	o.SofRaceName = &v
}

func (o UniverseGraphicsGraphicIdGet) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UniverseGraphicsGraphicIdGet) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.CollisionFile) {
		toSerialize["collision_file"] = o.CollisionFile
	}
	if !IsNil(o.GraphicFile) {
		toSerialize["graphic_file"] = o.GraphicFile
	}
	toSerialize["graphic_id"] = o.GraphicId
	if !IsNil(o.IconFolder) {
		toSerialize["icon_folder"] = o.IconFolder
	}
	if !IsNil(o.SofDna) {
		toSerialize["sof_dna"] = o.SofDna
	}
	if !IsNil(o.SofFationName) {
		toSerialize["sof_fation_name"] = o.SofFationName
	}
	if !IsNil(o.SofHullName) {
		toSerialize["sof_hull_name"] = o.SofHullName
	}
	if !IsNil(o.SofRaceName) {
		toSerialize["sof_race_name"] = o.SofRaceName
	}
	return toSerialize, nil
}

func (o *UniverseGraphicsGraphicIdGet) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"graphic_id",
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

	varUniverseGraphicsGraphicIdGet := _UniverseGraphicsGraphicIdGet{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varUniverseGraphicsGraphicIdGet)

	if err != nil {
		return err
	}

	*o = UniverseGraphicsGraphicIdGet(varUniverseGraphicsGraphicIdGet)

	return err
}

type NullableUniverseGraphicsGraphicIdGet struct {
	value *UniverseGraphicsGraphicIdGet
	isSet bool
}

func (v NullableUniverseGraphicsGraphicIdGet) Get() *UniverseGraphicsGraphicIdGet {
	return v.value
}

func (v *NullableUniverseGraphicsGraphicIdGet) Set(val *UniverseGraphicsGraphicIdGet) {
	v.value = val
	v.isSet = true
}

func (v NullableUniverseGraphicsGraphicIdGet) IsSet() bool {
	return v.isSet
}

func (v *NullableUniverseGraphicsGraphicIdGet) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUniverseGraphicsGraphicIdGet(val *UniverseGraphicsGraphicIdGet) *NullableUniverseGraphicsGraphicIdGet {
	return &NullableUniverseGraphicsGraphicIdGet{value: val, isSet: true}
}

func (v NullableUniverseGraphicsGraphicIdGet) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUniverseGraphicsGraphicIdGet) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


