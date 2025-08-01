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

// checks if the CharactersCharacterIdNotificationsContactsGetInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CharactersCharacterIdNotificationsContactsGetInner{}

// CharactersCharacterIdNotificationsContactsGetInner struct for CharactersCharacterIdNotificationsContactsGetInner
type CharactersCharacterIdNotificationsContactsGetInner struct {
	Message string `json:"message"`
	NotificationId int64 `json:"notification_id"`
	SendDate time.Time `json:"send_date"`
	SenderCharacterId int64 `json:"sender_character_id"`
	// A number representing the standing level the receiver has been added at by the sender. The standing levels are as follows: -10 -> Terrible | -5 -> Bad |  0 -> Neutral |  5 -> Good |  10 -> Excellent
	StandingLevel float64 `json:"standing_level"`
}

type _CharactersCharacterIdNotificationsContactsGetInner CharactersCharacterIdNotificationsContactsGetInner

// NewCharactersCharacterIdNotificationsContactsGetInner instantiates a new CharactersCharacterIdNotificationsContactsGetInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCharactersCharacterIdNotificationsContactsGetInner(message string, notificationId int64, sendDate time.Time, senderCharacterId int64, standingLevel float64) *CharactersCharacterIdNotificationsContactsGetInner {
	this := CharactersCharacterIdNotificationsContactsGetInner{}
	this.Message = message
	this.NotificationId = notificationId
	this.SendDate = sendDate
	this.SenderCharacterId = senderCharacterId
	this.StandingLevel = standingLevel
	return &this
}

// NewCharactersCharacterIdNotificationsContactsGetInnerWithDefaults instantiates a new CharactersCharacterIdNotificationsContactsGetInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCharactersCharacterIdNotificationsContactsGetInnerWithDefaults() *CharactersCharacterIdNotificationsContactsGetInner {
	this := CharactersCharacterIdNotificationsContactsGetInner{}
	return &this
}

// GetMessage returns the Message field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetMessage() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Message
}

// GetMessageOk returns a tuple with the Message field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetMessageOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Message, true
}

// SetMessage sets field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) SetMessage(v string) {
	o.Message = v
}

// GetNotificationId returns the NotificationId field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetNotificationId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.NotificationId
}

// GetNotificationIdOk returns a tuple with the NotificationId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetNotificationIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.NotificationId, true
}

// SetNotificationId sets field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) SetNotificationId(v int64) {
	o.NotificationId = v
}

// GetSendDate returns the SendDate field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetSendDate() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.SendDate
}

// GetSendDateOk returns a tuple with the SendDate field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetSendDateOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SendDate, true
}

// SetSendDate sets field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) SetSendDate(v time.Time) {
	o.SendDate = v
}

// GetSenderCharacterId returns the SenderCharacterId field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetSenderCharacterId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.SenderCharacterId
}

// GetSenderCharacterIdOk returns a tuple with the SenderCharacterId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetSenderCharacterIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SenderCharacterId, true
}

// SetSenderCharacterId sets field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) SetSenderCharacterId(v int64) {
	o.SenderCharacterId = v
}

// GetStandingLevel returns the StandingLevel field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetStandingLevel() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.StandingLevel
}

// GetStandingLevelOk returns a tuple with the StandingLevel field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdNotificationsContactsGetInner) GetStandingLevelOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.StandingLevel, true
}

// SetStandingLevel sets field value
func (o *CharactersCharacterIdNotificationsContactsGetInner) SetStandingLevel(v float64) {
	o.StandingLevel = v
}

func (o CharactersCharacterIdNotificationsContactsGetInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CharactersCharacterIdNotificationsContactsGetInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["message"] = o.Message
	toSerialize["notification_id"] = o.NotificationId
	toSerialize["send_date"] = o.SendDate
	toSerialize["sender_character_id"] = o.SenderCharacterId
	toSerialize["standing_level"] = o.StandingLevel
	return toSerialize, nil
}

func (o *CharactersCharacterIdNotificationsContactsGetInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"message",
		"notification_id",
		"send_date",
		"sender_character_id",
		"standing_level",
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

	varCharactersCharacterIdNotificationsContactsGetInner := _CharactersCharacterIdNotificationsContactsGetInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCharactersCharacterIdNotificationsContactsGetInner)

	if err != nil {
		return err
	}

	*o = CharactersCharacterIdNotificationsContactsGetInner(varCharactersCharacterIdNotificationsContactsGetInner)

	return err
}

type NullableCharactersCharacterIdNotificationsContactsGetInner struct {
	value *CharactersCharacterIdNotificationsContactsGetInner
	isSet bool
}

func (v NullableCharactersCharacterIdNotificationsContactsGetInner) Get() *CharactersCharacterIdNotificationsContactsGetInner {
	return v.value
}

func (v *NullableCharactersCharacterIdNotificationsContactsGetInner) Set(val *CharactersCharacterIdNotificationsContactsGetInner) {
	v.value = val
	v.isSet = true
}

func (v NullableCharactersCharacterIdNotificationsContactsGetInner) IsSet() bool {
	return v.isSet
}

func (v *NullableCharactersCharacterIdNotificationsContactsGetInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCharactersCharacterIdNotificationsContactsGetInner(val *CharactersCharacterIdNotificationsContactsGetInner) *NullableCharactersCharacterIdNotificationsContactsGetInner {
	return &NullableCharactersCharacterIdNotificationsContactsGetInner{value: val, isSet: true}
}

func (v NullableCharactersCharacterIdNotificationsContactsGetInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCharactersCharacterIdNotificationsContactsGetInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


