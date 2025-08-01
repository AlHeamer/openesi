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

// checks if the KillmailsKillmailIdKillmailHashGetAttackersInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &KillmailsKillmailIdKillmailHashGetAttackersInner{}

// KillmailsKillmailIdKillmailHashGetAttackersInner attacker object
type KillmailsKillmailIdKillmailHashGetAttackersInner struct {
	AllianceId *int64 `json:"alliance_id,omitempty"`
	CharacterId *int64 `json:"character_id,omitempty"`
	CorporationId *int64 `json:"corporation_id,omitempty"`
	DamageDone int64 `json:"damage_done"`
	FactionId *int64 `json:"faction_id,omitempty"`
	// Was the attacker the one to achieve the final blow 
	FinalBlow bool `json:"final_blow"`
	// Security status for the attacker 
	SecurityStatus float64 `json:"security_status"`
	// What ship was the attacker flying 
	ShipTypeId *int64 `json:"ship_type_id,omitempty"`
	// What weapon was used by the attacker for the kill 
	WeaponTypeId *int64 `json:"weapon_type_id,omitempty"`
}

type _KillmailsKillmailIdKillmailHashGetAttackersInner KillmailsKillmailIdKillmailHashGetAttackersInner

// NewKillmailsKillmailIdKillmailHashGetAttackersInner instantiates a new KillmailsKillmailIdKillmailHashGetAttackersInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewKillmailsKillmailIdKillmailHashGetAttackersInner(damageDone int64, finalBlow bool, securityStatus float64) *KillmailsKillmailIdKillmailHashGetAttackersInner {
	this := KillmailsKillmailIdKillmailHashGetAttackersInner{}
	this.DamageDone = damageDone
	this.FinalBlow = finalBlow
	this.SecurityStatus = securityStatus
	return &this
}

// NewKillmailsKillmailIdKillmailHashGetAttackersInnerWithDefaults instantiates a new KillmailsKillmailIdKillmailHashGetAttackersInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewKillmailsKillmailIdKillmailHashGetAttackersInnerWithDefaults() *KillmailsKillmailIdKillmailHashGetAttackersInner {
	this := KillmailsKillmailIdKillmailHashGetAttackersInner{}
	return &this
}

// GetAllianceId returns the AllianceId field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetAllianceId() int64 {
	if o == nil || IsNil(o.AllianceId) {
		var ret int64
		return ret
	}
	return *o.AllianceId
}

// GetAllianceIdOk returns a tuple with the AllianceId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetAllianceIdOk() (*int64, bool) {
	if o == nil || IsNil(o.AllianceId) {
		return nil, false
	}
	return o.AllianceId, true
}

// HasAllianceId returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) HasAllianceId() bool {
	if o != nil && !IsNil(o.AllianceId) {
		return true
	}

	return false
}

// SetAllianceId gets a reference to the given int64 and assigns it to the AllianceId field.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetAllianceId(v int64) {
	o.AllianceId = &v
}

// GetCharacterId returns the CharacterId field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetCharacterId() int64 {
	if o == nil || IsNil(o.CharacterId) {
		var ret int64
		return ret
	}
	return *o.CharacterId
}

// GetCharacterIdOk returns a tuple with the CharacterId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetCharacterIdOk() (*int64, bool) {
	if o == nil || IsNil(o.CharacterId) {
		return nil, false
	}
	return o.CharacterId, true
}

// HasCharacterId returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) HasCharacterId() bool {
	if o != nil && !IsNil(o.CharacterId) {
		return true
	}

	return false
}

// SetCharacterId gets a reference to the given int64 and assigns it to the CharacterId field.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetCharacterId(v int64) {
	o.CharacterId = &v
}

// GetCorporationId returns the CorporationId field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetCorporationId() int64 {
	if o == nil || IsNil(o.CorporationId) {
		var ret int64
		return ret
	}
	return *o.CorporationId
}

// GetCorporationIdOk returns a tuple with the CorporationId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetCorporationIdOk() (*int64, bool) {
	if o == nil || IsNil(o.CorporationId) {
		return nil, false
	}
	return o.CorporationId, true
}

// HasCorporationId returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) HasCorporationId() bool {
	if o != nil && !IsNil(o.CorporationId) {
		return true
	}

	return false
}

// SetCorporationId gets a reference to the given int64 and assigns it to the CorporationId field.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetCorporationId(v int64) {
	o.CorporationId = &v
}

// GetDamageDone returns the DamageDone field value
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetDamageDone() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.DamageDone
}

// GetDamageDoneOk returns a tuple with the DamageDone field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetDamageDoneOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.DamageDone, true
}

// SetDamageDone sets field value
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetDamageDone(v int64) {
	o.DamageDone = v
}

// GetFactionId returns the FactionId field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetFactionId() int64 {
	if o == nil || IsNil(o.FactionId) {
		var ret int64
		return ret
	}
	return *o.FactionId
}

// GetFactionIdOk returns a tuple with the FactionId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetFactionIdOk() (*int64, bool) {
	if o == nil || IsNil(o.FactionId) {
		return nil, false
	}
	return o.FactionId, true
}

// HasFactionId returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) HasFactionId() bool {
	if o != nil && !IsNil(o.FactionId) {
		return true
	}

	return false
}

// SetFactionId gets a reference to the given int64 and assigns it to the FactionId field.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetFactionId(v int64) {
	o.FactionId = &v
}

// GetFinalBlow returns the FinalBlow field value
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetFinalBlow() bool {
	if o == nil {
		var ret bool
		return ret
	}

	return o.FinalBlow
}

// GetFinalBlowOk returns a tuple with the FinalBlow field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetFinalBlowOk() (*bool, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FinalBlow, true
}

// SetFinalBlow sets field value
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetFinalBlow(v bool) {
	o.FinalBlow = v
}

// GetSecurityStatus returns the SecurityStatus field value
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetSecurityStatus() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.SecurityStatus
}

// GetSecurityStatusOk returns a tuple with the SecurityStatus field value
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetSecurityStatusOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SecurityStatus, true
}

// SetSecurityStatus sets field value
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetSecurityStatus(v float64) {
	o.SecurityStatus = v
}

// GetShipTypeId returns the ShipTypeId field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetShipTypeId() int64 {
	if o == nil || IsNil(o.ShipTypeId) {
		var ret int64
		return ret
	}
	return *o.ShipTypeId
}

// GetShipTypeIdOk returns a tuple with the ShipTypeId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetShipTypeIdOk() (*int64, bool) {
	if o == nil || IsNil(o.ShipTypeId) {
		return nil, false
	}
	return o.ShipTypeId, true
}

// HasShipTypeId returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) HasShipTypeId() bool {
	if o != nil && !IsNil(o.ShipTypeId) {
		return true
	}

	return false
}

// SetShipTypeId gets a reference to the given int64 and assigns it to the ShipTypeId field.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetShipTypeId(v int64) {
	o.ShipTypeId = &v
}

// GetWeaponTypeId returns the WeaponTypeId field value if set, zero value otherwise.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetWeaponTypeId() int64 {
	if o == nil || IsNil(o.WeaponTypeId) {
		var ret int64
		return ret
	}
	return *o.WeaponTypeId
}

// GetWeaponTypeIdOk returns a tuple with the WeaponTypeId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) GetWeaponTypeIdOk() (*int64, bool) {
	if o == nil || IsNil(o.WeaponTypeId) {
		return nil, false
	}
	return o.WeaponTypeId, true
}

// HasWeaponTypeId returns a boolean if a field has been set.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) HasWeaponTypeId() bool {
	if o != nil && !IsNil(o.WeaponTypeId) {
		return true
	}

	return false
}

// SetWeaponTypeId gets a reference to the given int64 and assigns it to the WeaponTypeId field.
func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) SetWeaponTypeId(v int64) {
	o.WeaponTypeId = &v
}

func (o KillmailsKillmailIdKillmailHashGetAttackersInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o KillmailsKillmailIdKillmailHashGetAttackersInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.AllianceId) {
		toSerialize["alliance_id"] = o.AllianceId
	}
	if !IsNil(o.CharacterId) {
		toSerialize["character_id"] = o.CharacterId
	}
	if !IsNil(o.CorporationId) {
		toSerialize["corporation_id"] = o.CorporationId
	}
	toSerialize["damage_done"] = o.DamageDone
	if !IsNil(o.FactionId) {
		toSerialize["faction_id"] = o.FactionId
	}
	toSerialize["final_blow"] = o.FinalBlow
	toSerialize["security_status"] = o.SecurityStatus
	if !IsNil(o.ShipTypeId) {
		toSerialize["ship_type_id"] = o.ShipTypeId
	}
	if !IsNil(o.WeaponTypeId) {
		toSerialize["weapon_type_id"] = o.WeaponTypeId
	}
	return toSerialize, nil
}

func (o *KillmailsKillmailIdKillmailHashGetAttackersInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"damage_done",
		"final_blow",
		"security_status",
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

	varKillmailsKillmailIdKillmailHashGetAttackersInner := _KillmailsKillmailIdKillmailHashGetAttackersInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varKillmailsKillmailIdKillmailHashGetAttackersInner)

	if err != nil {
		return err
	}

	*o = KillmailsKillmailIdKillmailHashGetAttackersInner(varKillmailsKillmailIdKillmailHashGetAttackersInner)

	return err
}

type NullableKillmailsKillmailIdKillmailHashGetAttackersInner struct {
	value *KillmailsKillmailIdKillmailHashGetAttackersInner
	isSet bool
}

func (v NullableKillmailsKillmailIdKillmailHashGetAttackersInner) Get() *KillmailsKillmailIdKillmailHashGetAttackersInner {
	return v.value
}

func (v *NullableKillmailsKillmailIdKillmailHashGetAttackersInner) Set(val *KillmailsKillmailIdKillmailHashGetAttackersInner) {
	v.value = val
	v.isSet = true
}

func (v NullableKillmailsKillmailIdKillmailHashGetAttackersInner) IsSet() bool {
	return v.isSet
}

func (v *NullableKillmailsKillmailIdKillmailHashGetAttackersInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKillmailsKillmailIdKillmailHashGetAttackersInner(val *KillmailsKillmailIdKillmailHashGetAttackersInner) *NullableKillmailsKillmailIdKillmailHashGetAttackersInner {
	return &NullableKillmailsKillmailIdKillmailHashGetAttackersInner{value: val, isSet: true}
}

func (v NullableKillmailsKillmailIdKillmailHashGetAttackersInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKillmailsKillmailIdKillmailHashGetAttackersInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


