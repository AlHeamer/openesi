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

// checks if the DogmaEffectsEffectIdGet type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &DogmaEffectsEffectIdGet{}

// DogmaEffectsEffectIdGet struct for DogmaEffectsEffectIdGet
type DogmaEffectsEffectIdGet struct {
	Description *string `json:"description,omitempty"`
	DisallowAutoRepeat *bool `json:"disallow_auto_repeat,omitempty"`
	DischargeAttributeId *int64 `json:"discharge_attribute_id,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	DurationAttributeId *int64 `json:"duration_attribute_id,omitempty"`
	EffectCategory *int64 `json:"effect_category,omitempty"`
	EffectId int64 `json:"effect_id"`
	ElectronicChance *bool `json:"electronic_chance,omitempty"`
	FalloffAttributeId *int64 `json:"falloff_attribute_id,omitempty"`
	IconId *int64 `json:"icon_id,omitempty"`
	IsAssistance *bool `json:"is_assistance,omitempty"`
	IsOffensive *bool `json:"is_offensive,omitempty"`
	IsWarpSafe *bool `json:"is_warp_safe,omitempty"`
	Modifiers []DogmaEffectsEffectIdGetModifiersInner `json:"modifiers,omitempty"`
	Name *string `json:"name,omitempty"`
	PostExpression *int64 `json:"post_expression,omitempty"`
	PreExpression *int64 `json:"pre_expression,omitempty"`
	Published *bool `json:"published,omitempty"`
	RangeAttributeId *int64 `json:"range_attribute_id,omitempty"`
	RangeChance *bool `json:"range_chance,omitempty"`
	TrackingSpeedAttributeId *int64 `json:"tracking_speed_attribute_id,omitempty"`
}

type _DogmaEffectsEffectIdGet DogmaEffectsEffectIdGet

// NewDogmaEffectsEffectIdGet instantiates a new DogmaEffectsEffectIdGet object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDogmaEffectsEffectIdGet(effectId int64) *DogmaEffectsEffectIdGet {
	this := DogmaEffectsEffectIdGet{}
	this.EffectId = effectId
	return &this
}

// NewDogmaEffectsEffectIdGetWithDefaults instantiates a new DogmaEffectsEffectIdGet object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDogmaEffectsEffectIdGetWithDefaults() *DogmaEffectsEffectIdGet {
	this := DogmaEffectsEffectIdGet{}
	return &this
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetDescription() string {
	if o == nil || IsNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetDescriptionOk() (*string, bool) {
	if o == nil || IsNil(o.Description) {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasDescription() bool {
	if o != nil && !IsNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *DogmaEffectsEffectIdGet) SetDescription(v string) {
	o.Description = &v
}

// GetDisallowAutoRepeat returns the DisallowAutoRepeat field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetDisallowAutoRepeat() bool {
	if o == nil || IsNil(o.DisallowAutoRepeat) {
		var ret bool
		return ret
	}
	return *o.DisallowAutoRepeat
}

// GetDisallowAutoRepeatOk returns a tuple with the DisallowAutoRepeat field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetDisallowAutoRepeatOk() (*bool, bool) {
	if o == nil || IsNil(o.DisallowAutoRepeat) {
		return nil, false
	}
	return o.DisallowAutoRepeat, true
}

// HasDisallowAutoRepeat returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasDisallowAutoRepeat() bool {
	if o != nil && !IsNil(o.DisallowAutoRepeat) {
		return true
	}

	return false
}

// SetDisallowAutoRepeat gets a reference to the given bool and assigns it to the DisallowAutoRepeat field.
func (o *DogmaEffectsEffectIdGet) SetDisallowAutoRepeat(v bool) {
	o.DisallowAutoRepeat = &v
}

// GetDischargeAttributeId returns the DischargeAttributeId field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetDischargeAttributeId() int64 {
	if o == nil || IsNil(o.DischargeAttributeId) {
		var ret int64
		return ret
	}
	return *o.DischargeAttributeId
}

// GetDischargeAttributeIdOk returns a tuple with the DischargeAttributeId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetDischargeAttributeIdOk() (*int64, bool) {
	if o == nil || IsNil(o.DischargeAttributeId) {
		return nil, false
	}
	return o.DischargeAttributeId, true
}

// HasDischargeAttributeId returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasDischargeAttributeId() bool {
	if o != nil && !IsNil(o.DischargeAttributeId) {
		return true
	}

	return false
}

// SetDischargeAttributeId gets a reference to the given int64 and assigns it to the DischargeAttributeId field.
func (o *DogmaEffectsEffectIdGet) SetDischargeAttributeId(v int64) {
	o.DischargeAttributeId = &v
}

// GetDisplayName returns the DisplayName field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetDisplayName() string {
	if o == nil || IsNil(o.DisplayName) {
		var ret string
		return ret
	}
	return *o.DisplayName
}

// GetDisplayNameOk returns a tuple with the DisplayName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetDisplayNameOk() (*string, bool) {
	if o == nil || IsNil(o.DisplayName) {
		return nil, false
	}
	return o.DisplayName, true
}

// HasDisplayName returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasDisplayName() bool {
	if o != nil && !IsNil(o.DisplayName) {
		return true
	}

	return false
}

// SetDisplayName gets a reference to the given string and assigns it to the DisplayName field.
func (o *DogmaEffectsEffectIdGet) SetDisplayName(v string) {
	o.DisplayName = &v
}

// GetDurationAttributeId returns the DurationAttributeId field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetDurationAttributeId() int64 {
	if o == nil || IsNil(o.DurationAttributeId) {
		var ret int64
		return ret
	}
	return *o.DurationAttributeId
}

// GetDurationAttributeIdOk returns a tuple with the DurationAttributeId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetDurationAttributeIdOk() (*int64, bool) {
	if o == nil || IsNil(o.DurationAttributeId) {
		return nil, false
	}
	return o.DurationAttributeId, true
}

// HasDurationAttributeId returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasDurationAttributeId() bool {
	if o != nil && !IsNil(o.DurationAttributeId) {
		return true
	}

	return false
}

// SetDurationAttributeId gets a reference to the given int64 and assigns it to the DurationAttributeId field.
func (o *DogmaEffectsEffectIdGet) SetDurationAttributeId(v int64) {
	o.DurationAttributeId = &v
}

// GetEffectCategory returns the EffectCategory field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetEffectCategory() int64 {
	if o == nil || IsNil(o.EffectCategory) {
		var ret int64
		return ret
	}
	return *o.EffectCategory
}

// GetEffectCategoryOk returns a tuple with the EffectCategory field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetEffectCategoryOk() (*int64, bool) {
	if o == nil || IsNil(o.EffectCategory) {
		return nil, false
	}
	return o.EffectCategory, true
}

// HasEffectCategory returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasEffectCategory() bool {
	if o != nil && !IsNil(o.EffectCategory) {
		return true
	}

	return false
}

// SetEffectCategory gets a reference to the given int64 and assigns it to the EffectCategory field.
func (o *DogmaEffectsEffectIdGet) SetEffectCategory(v int64) {
	o.EffectCategory = &v
}

// GetEffectId returns the EffectId field value
func (o *DogmaEffectsEffectIdGet) GetEffectId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.EffectId
}

// GetEffectIdOk returns a tuple with the EffectId field value
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetEffectIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.EffectId, true
}

// SetEffectId sets field value
func (o *DogmaEffectsEffectIdGet) SetEffectId(v int64) {
	o.EffectId = v
}

// GetElectronicChance returns the ElectronicChance field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetElectronicChance() bool {
	if o == nil || IsNil(o.ElectronicChance) {
		var ret bool
		return ret
	}
	return *o.ElectronicChance
}

// GetElectronicChanceOk returns a tuple with the ElectronicChance field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetElectronicChanceOk() (*bool, bool) {
	if o == nil || IsNil(o.ElectronicChance) {
		return nil, false
	}
	return o.ElectronicChance, true
}

// HasElectronicChance returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasElectronicChance() bool {
	if o != nil && !IsNil(o.ElectronicChance) {
		return true
	}

	return false
}

// SetElectronicChance gets a reference to the given bool and assigns it to the ElectronicChance field.
func (o *DogmaEffectsEffectIdGet) SetElectronicChance(v bool) {
	o.ElectronicChance = &v
}

// GetFalloffAttributeId returns the FalloffAttributeId field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetFalloffAttributeId() int64 {
	if o == nil || IsNil(o.FalloffAttributeId) {
		var ret int64
		return ret
	}
	return *o.FalloffAttributeId
}

// GetFalloffAttributeIdOk returns a tuple with the FalloffAttributeId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetFalloffAttributeIdOk() (*int64, bool) {
	if o == nil || IsNil(o.FalloffAttributeId) {
		return nil, false
	}
	return o.FalloffAttributeId, true
}

// HasFalloffAttributeId returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasFalloffAttributeId() bool {
	if o != nil && !IsNil(o.FalloffAttributeId) {
		return true
	}

	return false
}

// SetFalloffAttributeId gets a reference to the given int64 and assigns it to the FalloffAttributeId field.
func (o *DogmaEffectsEffectIdGet) SetFalloffAttributeId(v int64) {
	o.FalloffAttributeId = &v
}

// GetIconId returns the IconId field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetIconId() int64 {
	if o == nil || IsNil(o.IconId) {
		var ret int64
		return ret
	}
	return *o.IconId
}

// GetIconIdOk returns a tuple with the IconId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetIconIdOk() (*int64, bool) {
	if o == nil || IsNil(o.IconId) {
		return nil, false
	}
	return o.IconId, true
}

// HasIconId returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasIconId() bool {
	if o != nil && !IsNil(o.IconId) {
		return true
	}

	return false
}

// SetIconId gets a reference to the given int64 and assigns it to the IconId field.
func (o *DogmaEffectsEffectIdGet) SetIconId(v int64) {
	o.IconId = &v
}

// GetIsAssistance returns the IsAssistance field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetIsAssistance() bool {
	if o == nil || IsNil(o.IsAssistance) {
		var ret bool
		return ret
	}
	return *o.IsAssistance
}

// GetIsAssistanceOk returns a tuple with the IsAssistance field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetIsAssistanceOk() (*bool, bool) {
	if o == nil || IsNil(o.IsAssistance) {
		return nil, false
	}
	return o.IsAssistance, true
}

// HasIsAssistance returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasIsAssistance() bool {
	if o != nil && !IsNil(o.IsAssistance) {
		return true
	}

	return false
}

// SetIsAssistance gets a reference to the given bool and assigns it to the IsAssistance field.
func (o *DogmaEffectsEffectIdGet) SetIsAssistance(v bool) {
	o.IsAssistance = &v
}

// GetIsOffensive returns the IsOffensive field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetIsOffensive() bool {
	if o == nil || IsNil(o.IsOffensive) {
		var ret bool
		return ret
	}
	return *o.IsOffensive
}

// GetIsOffensiveOk returns a tuple with the IsOffensive field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetIsOffensiveOk() (*bool, bool) {
	if o == nil || IsNil(o.IsOffensive) {
		return nil, false
	}
	return o.IsOffensive, true
}

// HasIsOffensive returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasIsOffensive() bool {
	if o != nil && !IsNil(o.IsOffensive) {
		return true
	}

	return false
}

// SetIsOffensive gets a reference to the given bool and assigns it to the IsOffensive field.
func (o *DogmaEffectsEffectIdGet) SetIsOffensive(v bool) {
	o.IsOffensive = &v
}

// GetIsWarpSafe returns the IsWarpSafe field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetIsWarpSafe() bool {
	if o == nil || IsNil(o.IsWarpSafe) {
		var ret bool
		return ret
	}
	return *o.IsWarpSafe
}

// GetIsWarpSafeOk returns a tuple with the IsWarpSafe field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetIsWarpSafeOk() (*bool, bool) {
	if o == nil || IsNil(o.IsWarpSafe) {
		return nil, false
	}
	return o.IsWarpSafe, true
}

// HasIsWarpSafe returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasIsWarpSafe() bool {
	if o != nil && !IsNil(o.IsWarpSafe) {
		return true
	}

	return false
}

// SetIsWarpSafe gets a reference to the given bool and assigns it to the IsWarpSafe field.
func (o *DogmaEffectsEffectIdGet) SetIsWarpSafe(v bool) {
	o.IsWarpSafe = &v
}

// GetModifiers returns the Modifiers field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetModifiers() []DogmaEffectsEffectIdGetModifiersInner {
	if o == nil || IsNil(o.Modifiers) {
		var ret []DogmaEffectsEffectIdGetModifiersInner
		return ret
	}
	return o.Modifiers
}

// GetModifiersOk returns a tuple with the Modifiers field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetModifiersOk() ([]DogmaEffectsEffectIdGetModifiersInner, bool) {
	if o == nil || IsNil(o.Modifiers) {
		return nil, false
	}
	return o.Modifiers, true
}

// HasModifiers returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasModifiers() bool {
	if o != nil && !IsNil(o.Modifiers) {
		return true
	}

	return false
}

// SetModifiers gets a reference to the given []DogmaEffectsEffectIdGetModifiersInner and assigns it to the Modifiers field.
func (o *DogmaEffectsEffectIdGet) SetModifiers(v []DogmaEffectsEffectIdGetModifiersInner) {
	o.Modifiers = v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetName() string {
	if o == nil || IsNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetNameOk() (*string, bool) {
	if o == nil || IsNil(o.Name) {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasName() bool {
	if o != nil && !IsNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *DogmaEffectsEffectIdGet) SetName(v string) {
	o.Name = &v
}

// GetPostExpression returns the PostExpression field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetPostExpression() int64 {
	if o == nil || IsNil(o.PostExpression) {
		var ret int64
		return ret
	}
	return *o.PostExpression
}

// GetPostExpressionOk returns a tuple with the PostExpression field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetPostExpressionOk() (*int64, bool) {
	if o == nil || IsNil(o.PostExpression) {
		return nil, false
	}
	return o.PostExpression, true
}

// HasPostExpression returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasPostExpression() bool {
	if o != nil && !IsNil(o.PostExpression) {
		return true
	}

	return false
}

// SetPostExpression gets a reference to the given int64 and assigns it to the PostExpression field.
func (o *DogmaEffectsEffectIdGet) SetPostExpression(v int64) {
	o.PostExpression = &v
}

// GetPreExpression returns the PreExpression field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetPreExpression() int64 {
	if o == nil || IsNil(o.PreExpression) {
		var ret int64
		return ret
	}
	return *o.PreExpression
}

// GetPreExpressionOk returns a tuple with the PreExpression field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetPreExpressionOk() (*int64, bool) {
	if o == nil || IsNil(o.PreExpression) {
		return nil, false
	}
	return o.PreExpression, true
}

// HasPreExpression returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasPreExpression() bool {
	if o != nil && !IsNil(o.PreExpression) {
		return true
	}

	return false
}

// SetPreExpression gets a reference to the given int64 and assigns it to the PreExpression field.
func (o *DogmaEffectsEffectIdGet) SetPreExpression(v int64) {
	o.PreExpression = &v
}

// GetPublished returns the Published field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetPublished() bool {
	if o == nil || IsNil(o.Published) {
		var ret bool
		return ret
	}
	return *o.Published
}

// GetPublishedOk returns a tuple with the Published field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetPublishedOk() (*bool, bool) {
	if o == nil || IsNil(o.Published) {
		return nil, false
	}
	return o.Published, true
}

// HasPublished returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasPublished() bool {
	if o != nil && !IsNil(o.Published) {
		return true
	}

	return false
}

// SetPublished gets a reference to the given bool and assigns it to the Published field.
func (o *DogmaEffectsEffectIdGet) SetPublished(v bool) {
	o.Published = &v
}

// GetRangeAttributeId returns the RangeAttributeId field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetRangeAttributeId() int64 {
	if o == nil || IsNil(o.RangeAttributeId) {
		var ret int64
		return ret
	}
	return *o.RangeAttributeId
}

// GetRangeAttributeIdOk returns a tuple with the RangeAttributeId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetRangeAttributeIdOk() (*int64, bool) {
	if o == nil || IsNil(o.RangeAttributeId) {
		return nil, false
	}
	return o.RangeAttributeId, true
}

// HasRangeAttributeId returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasRangeAttributeId() bool {
	if o != nil && !IsNil(o.RangeAttributeId) {
		return true
	}

	return false
}

// SetRangeAttributeId gets a reference to the given int64 and assigns it to the RangeAttributeId field.
func (o *DogmaEffectsEffectIdGet) SetRangeAttributeId(v int64) {
	o.RangeAttributeId = &v
}

// GetRangeChance returns the RangeChance field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetRangeChance() bool {
	if o == nil || IsNil(o.RangeChance) {
		var ret bool
		return ret
	}
	return *o.RangeChance
}

// GetRangeChanceOk returns a tuple with the RangeChance field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetRangeChanceOk() (*bool, bool) {
	if o == nil || IsNil(o.RangeChance) {
		return nil, false
	}
	return o.RangeChance, true
}

// HasRangeChance returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasRangeChance() bool {
	if o != nil && !IsNil(o.RangeChance) {
		return true
	}

	return false
}

// SetRangeChance gets a reference to the given bool and assigns it to the RangeChance field.
func (o *DogmaEffectsEffectIdGet) SetRangeChance(v bool) {
	o.RangeChance = &v
}

// GetTrackingSpeedAttributeId returns the TrackingSpeedAttributeId field value if set, zero value otherwise.
func (o *DogmaEffectsEffectIdGet) GetTrackingSpeedAttributeId() int64 {
	if o == nil || IsNil(o.TrackingSpeedAttributeId) {
		var ret int64
		return ret
	}
	return *o.TrackingSpeedAttributeId
}

// GetTrackingSpeedAttributeIdOk returns a tuple with the TrackingSpeedAttributeId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DogmaEffectsEffectIdGet) GetTrackingSpeedAttributeIdOk() (*int64, bool) {
	if o == nil || IsNil(o.TrackingSpeedAttributeId) {
		return nil, false
	}
	return o.TrackingSpeedAttributeId, true
}

// HasTrackingSpeedAttributeId returns a boolean if a field has been set.
func (o *DogmaEffectsEffectIdGet) HasTrackingSpeedAttributeId() bool {
	if o != nil && !IsNil(o.TrackingSpeedAttributeId) {
		return true
	}

	return false
}

// SetTrackingSpeedAttributeId gets a reference to the given int64 and assigns it to the TrackingSpeedAttributeId field.
func (o *DogmaEffectsEffectIdGet) SetTrackingSpeedAttributeId(v int64) {
	o.TrackingSpeedAttributeId = &v
}

func (o DogmaEffectsEffectIdGet) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o DogmaEffectsEffectIdGet) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	if !IsNil(o.DisallowAutoRepeat) {
		toSerialize["disallow_auto_repeat"] = o.DisallowAutoRepeat
	}
	if !IsNil(o.DischargeAttributeId) {
		toSerialize["discharge_attribute_id"] = o.DischargeAttributeId
	}
	if !IsNil(o.DisplayName) {
		toSerialize["display_name"] = o.DisplayName
	}
	if !IsNil(o.DurationAttributeId) {
		toSerialize["duration_attribute_id"] = o.DurationAttributeId
	}
	if !IsNil(o.EffectCategory) {
		toSerialize["effect_category"] = o.EffectCategory
	}
	toSerialize["effect_id"] = o.EffectId
	if !IsNil(o.ElectronicChance) {
		toSerialize["electronic_chance"] = o.ElectronicChance
	}
	if !IsNil(o.FalloffAttributeId) {
		toSerialize["falloff_attribute_id"] = o.FalloffAttributeId
	}
	if !IsNil(o.IconId) {
		toSerialize["icon_id"] = o.IconId
	}
	if !IsNil(o.IsAssistance) {
		toSerialize["is_assistance"] = o.IsAssistance
	}
	if !IsNil(o.IsOffensive) {
		toSerialize["is_offensive"] = o.IsOffensive
	}
	if !IsNil(o.IsWarpSafe) {
		toSerialize["is_warp_safe"] = o.IsWarpSafe
	}
	if !IsNil(o.Modifiers) {
		toSerialize["modifiers"] = o.Modifiers
	}
	if !IsNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !IsNil(o.PostExpression) {
		toSerialize["post_expression"] = o.PostExpression
	}
	if !IsNil(o.PreExpression) {
		toSerialize["pre_expression"] = o.PreExpression
	}
	if !IsNil(o.Published) {
		toSerialize["published"] = o.Published
	}
	if !IsNil(o.RangeAttributeId) {
		toSerialize["range_attribute_id"] = o.RangeAttributeId
	}
	if !IsNil(o.RangeChance) {
		toSerialize["range_chance"] = o.RangeChance
	}
	if !IsNil(o.TrackingSpeedAttributeId) {
		toSerialize["tracking_speed_attribute_id"] = o.TrackingSpeedAttributeId
	}
	return toSerialize, nil
}

func (o *DogmaEffectsEffectIdGet) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"effect_id",
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

	varDogmaEffectsEffectIdGet := _DogmaEffectsEffectIdGet{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varDogmaEffectsEffectIdGet)

	if err != nil {
		return err
	}

	*o = DogmaEffectsEffectIdGet(varDogmaEffectsEffectIdGet)

	return err
}

type NullableDogmaEffectsEffectIdGet struct {
	value *DogmaEffectsEffectIdGet
	isSet bool
}

func (v NullableDogmaEffectsEffectIdGet) Get() *DogmaEffectsEffectIdGet {
	return v.value
}

func (v *NullableDogmaEffectsEffectIdGet) Set(val *DogmaEffectsEffectIdGet) {
	v.value = val
	v.isSet = true
}

func (v NullableDogmaEffectsEffectIdGet) IsSet() bool {
	return v.isSet
}

func (v *NullableDogmaEffectsEffectIdGet) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDogmaEffectsEffectIdGet(val *DogmaEffectsEffectIdGet) *NullableDogmaEffectsEffectIdGet {
	return &NullableDogmaEffectsEffectIdGet{value: val, isSet: true}
}

func (v NullableDogmaEffectsEffectIdGet) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDogmaEffectsEffectIdGet) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


