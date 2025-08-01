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

// checks if the CharactersCharacterIdIndustryJobsGetInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CharactersCharacterIdIndustryJobsGetInner{}

// CharactersCharacterIdIndustryJobsGetInner struct for CharactersCharacterIdIndustryJobsGetInner
type CharactersCharacterIdIndustryJobsGetInner struct {
	// Job activity ID
	ActivityId int64 `json:"activity_id"`
	BlueprintId int64 `json:"blueprint_id"`
	// Location ID of the location from which the blueprint was installed. Normally a station ID, but can also be an asset (e.g. container) or corporation facility
	BlueprintLocationId int64 `json:"blueprint_location_id"`
	BlueprintTypeId int64 `json:"blueprint_type_id"`
	// ID of the character which completed this job
	CompletedCharacterId *int64 `json:"completed_character_id,omitempty"`
	// Date and time when this job was completed
	CompletedDate *time.Time `json:"completed_date,omitempty"`
	// The sume of job installation fee and industry facility tax
	Cost *float64 `json:"cost,omitempty"`
	// Job duration in seconds
	Duration int64 `json:"duration"`
	// Date and time when this job finished
	EndDate time.Time `json:"end_date"`
	// ID of the facility where this job is running
	FacilityId int64 `json:"facility_id"`
	// ID of the character which installed this job
	InstallerId int64 `json:"installer_id"`
	// Unique job ID
	JobId int64 `json:"job_id"`
	// Number of runs blueprint is licensed for
	LicensedRuns *int64 `json:"licensed_runs,omitempty"`
	// Location ID of the location to which the output of the job will be delivered. Normally a station ID, but can also be a corporation facility
	OutputLocationId int64 `json:"output_location_id"`
	// Date and time when this job was paused (i.e. time when the facility where this job was installed went offline)
	PauseDate *time.Time `json:"pause_date,omitempty"`
	// Chance of success for invention
	Probability *float64 `json:"probability,omitempty"`
	// Type ID of product (manufactured, copied or invented)
	ProductTypeId *int64 `json:"product_type_id,omitempty"`
	// Number of runs for a manufacturing job, or number of copies to make for a blueprint copy
	Runs int64 `json:"runs"`
	// Date and time when this job started
	StartDate time.Time `json:"start_date"`
	// ID of the station where industry facility is located
	StationId int64 `json:"station_id"`
	Status string `json:"status"`
	// Number of successful runs for this job. Equal to runs unless this is an invention job
	SuccessfulRuns *int64 `json:"successful_runs,omitempty"`
}

type _CharactersCharacterIdIndustryJobsGetInner CharactersCharacterIdIndustryJobsGetInner

// NewCharactersCharacterIdIndustryJobsGetInner instantiates a new CharactersCharacterIdIndustryJobsGetInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCharactersCharacterIdIndustryJobsGetInner(activityId int64, blueprintId int64, blueprintLocationId int64, blueprintTypeId int64, duration int64, endDate time.Time, facilityId int64, installerId int64, jobId int64, outputLocationId int64, runs int64, startDate time.Time, stationId int64, status string) *CharactersCharacterIdIndustryJobsGetInner {
	this := CharactersCharacterIdIndustryJobsGetInner{}
	this.ActivityId = activityId
	this.BlueprintId = blueprintId
	this.BlueprintLocationId = blueprintLocationId
	this.BlueprintTypeId = blueprintTypeId
	this.Duration = duration
	this.EndDate = endDate
	this.FacilityId = facilityId
	this.InstallerId = installerId
	this.JobId = jobId
	this.OutputLocationId = outputLocationId
	this.Runs = runs
	this.StartDate = startDate
	this.StationId = stationId
	this.Status = status
	return &this
}

// NewCharactersCharacterIdIndustryJobsGetInnerWithDefaults instantiates a new CharactersCharacterIdIndustryJobsGetInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCharactersCharacterIdIndustryJobsGetInnerWithDefaults() *CharactersCharacterIdIndustryJobsGetInner {
	this := CharactersCharacterIdIndustryJobsGetInner{}
	return &this
}

// GetActivityId returns the ActivityId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetActivityId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.ActivityId
}

// GetActivityIdOk returns a tuple with the ActivityId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetActivityIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ActivityId, true
}

// SetActivityId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetActivityId(v int64) {
	o.ActivityId = v
}

// GetBlueprintId returns the BlueprintId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetBlueprintId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.BlueprintId
}

// GetBlueprintIdOk returns a tuple with the BlueprintId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetBlueprintIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.BlueprintId, true
}

// SetBlueprintId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetBlueprintId(v int64) {
	o.BlueprintId = v
}

// GetBlueprintLocationId returns the BlueprintLocationId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetBlueprintLocationId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.BlueprintLocationId
}

// GetBlueprintLocationIdOk returns a tuple with the BlueprintLocationId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetBlueprintLocationIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.BlueprintLocationId, true
}

// SetBlueprintLocationId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetBlueprintLocationId(v int64) {
	o.BlueprintLocationId = v
}

// GetBlueprintTypeId returns the BlueprintTypeId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetBlueprintTypeId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.BlueprintTypeId
}

// GetBlueprintTypeIdOk returns a tuple with the BlueprintTypeId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetBlueprintTypeIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.BlueprintTypeId, true
}

// SetBlueprintTypeId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetBlueprintTypeId(v int64) {
	o.BlueprintTypeId = v
}

// GetCompletedCharacterId returns the CompletedCharacterId field value if set, zero value otherwise.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetCompletedCharacterId() int64 {
	if o == nil || IsNil(o.CompletedCharacterId) {
		var ret int64
		return ret
	}
	return *o.CompletedCharacterId
}

// GetCompletedCharacterIdOk returns a tuple with the CompletedCharacterId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetCompletedCharacterIdOk() (*int64, bool) {
	if o == nil || IsNil(o.CompletedCharacterId) {
		return nil, false
	}
	return o.CompletedCharacterId, true
}

// HasCompletedCharacterId returns a boolean if a field has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) HasCompletedCharacterId() bool {
	if o != nil && !IsNil(o.CompletedCharacterId) {
		return true
	}

	return false
}

// SetCompletedCharacterId gets a reference to the given int64 and assigns it to the CompletedCharacterId field.
func (o *CharactersCharacterIdIndustryJobsGetInner) SetCompletedCharacterId(v int64) {
	o.CompletedCharacterId = &v
}

// GetCompletedDate returns the CompletedDate field value if set, zero value otherwise.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetCompletedDate() time.Time {
	if o == nil || IsNil(o.CompletedDate) {
		var ret time.Time
		return ret
	}
	return *o.CompletedDate
}

// GetCompletedDateOk returns a tuple with the CompletedDate field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetCompletedDateOk() (*time.Time, bool) {
	if o == nil || IsNil(o.CompletedDate) {
		return nil, false
	}
	return o.CompletedDate, true
}

// HasCompletedDate returns a boolean if a field has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) HasCompletedDate() bool {
	if o != nil && !IsNil(o.CompletedDate) {
		return true
	}

	return false
}

// SetCompletedDate gets a reference to the given time.Time and assigns it to the CompletedDate field.
func (o *CharactersCharacterIdIndustryJobsGetInner) SetCompletedDate(v time.Time) {
	o.CompletedDate = &v
}

// GetCost returns the Cost field value if set, zero value otherwise.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetCost() float64 {
	if o == nil || IsNil(o.Cost) {
		var ret float64
		return ret
	}
	return *o.Cost
}

// GetCostOk returns a tuple with the Cost field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetCostOk() (*float64, bool) {
	if o == nil || IsNil(o.Cost) {
		return nil, false
	}
	return o.Cost, true
}

// HasCost returns a boolean if a field has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) HasCost() bool {
	if o != nil && !IsNil(o.Cost) {
		return true
	}

	return false
}

// SetCost gets a reference to the given float64 and assigns it to the Cost field.
func (o *CharactersCharacterIdIndustryJobsGetInner) SetCost(v float64) {
	o.Cost = &v
}

// GetDuration returns the Duration field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetDuration() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Duration
}

// GetDurationOk returns a tuple with the Duration field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetDurationOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Duration, true
}

// SetDuration sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetDuration(v int64) {
	o.Duration = v
}

// GetEndDate returns the EndDate field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetEndDate() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.EndDate
}

// GetEndDateOk returns a tuple with the EndDate field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetEndDateOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.EndDate, true
}

// SetEndDate sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetEndDate(v time.Time) {
	o.EndDate = v
}

// GetFacilityId returns the FacilityId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetFacilityId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.FacilityId
}

// GetFacilityIdOk returns a tuple with the FacilityId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetFacilityIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FacilityId, true
}

// SetFacilityId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetFacilityId(v int64) {
	o.FacilityId = v
}

// GetInstallerId returns the InstallerId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetInstallerId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.InstallerId
}

// GetInstallerIdOk returns a tuple with the InstallerId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetInstallerIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.InstallerId, true
}

// SetInstallerId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetInstallerId(v int64) {
	o.InstallerId = v
}

// GetJobId returns the JobId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetJobId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.JobId
}

// GetJobIdOk returns a tuple with the JobId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetJobIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.JobId, true
}

// SetJobId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetJobId(v int64) {
	o.JobId = v
}

// GetLicensedRuns returns the LicensedRuns field value if set, zero value otherwise.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetLicensedRuns() int64 {
	if o == nil || IsNil(o.LicensedRuns) {
		var ret int64
		return ret
	}
	return *o.LicensedRuns
}

// GetLicensedRunsOk returns a tuple with the LicensedRuns field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetLicensedRunsOk() (*int64, bool) {
	if o == nil || IsNil(o.LicensedRuns) {
		return nil, false
	}
	return o.LicensedRuns, true
}

// HasLicensedRuns returns a boolean if a field has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) HasLicensedRuns() bool {
	if o != nil && !IsNil(o.LicensedRuns) {
		return true
	}

	return false
}

// SetLicensedRuns gets a reference to the given int64 and assigns it to the LicensedRuns field.
func (o *CharactersCharacterIdIndustryJobsGetInner) SetLicensedRuns(v int64) {
	o.LicensedRuns = &v
}

// GetOutputLocationId returns the OutputLocationId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetOutputLocationId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.OutputLocationId
}

// GetOutputLocationIdOk returns a tuple with the OutputLocationId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetOutputLocationIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.OutputLocationId, true
}

// SetOutputLocationId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetOutputLocationId(v int64) {
	o.OutputLocationId = v
}

// GetPauseDate returns the PauseDate field value if set, zero value otherwise.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetPauseDate() time.Time {
	if o == nil || IsNil(o.PauseDate) {
		var ret time.Time
		return ret
	}
	return *o.PauseDate
}

// GetPauseDateOk returns a tuple with the PauseDate field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetPauseDateOk() (*time.Time, bool) {
	if o == nil || IsNil(o.PauseDate) {
		return nil, false
	}
	return o.PauseDate, true
}

// HasPauseDate returns a boolean if a field has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) HasPauseDate() bool {
	if o != nil && !IsNil(o.PauseDate) {
		return true
	}

	return false
}

// SetPauseDate gets a reference to the given time.Time and assigns it to the PauseDate field.
func (o *CharactersCharacterIdIndustryJobsGetInner) SetPauseDate(v time.Time) {
	o.PauseDate = &v
}

// GetProbability returns the Probability field value if set, zero value otherwise.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetProbability() float64 {
	if o == nil || IsNil(o.Probability) {
		var ret float64
		return ret
	}
	return *o.Probability
}

// GetProbabilityOk returns a tuple with the Probability field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetProbabilityOk() (*float64, bool) {
	if o == nil || IsNil(o.Probability) {
		return nil, false
	}
	return o.Probability, true
}

// HasProbability returns a boolean if a field has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) HasProbability() bool {
	if o != nil && !IsNil(o.Probability) {
		return true
	}

	return false
}

// SetProbability gets a reference to the given float64 and assigns it to the Probability field.
func (o *CharactersCharacterIdIndustryJobsGetInner) SetProbability(v float64) {
	o.Probability = &v
}

// GetProductTypeId returns the ProductTypeId field value if set, zero value otherwise.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetProductTypeId() int64 {
	if o == nil || IsNil(o.ProductTypeId) {
		var ret int64
		return ret
	}
	return *o.ProductTypeId
}

// GetProductTypeIdOk returns a tuple with the ProductTypeId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetProductTypeIdOk() (*int64, bool) {
	if o == nil || IsNil(o.ProductTypeId) {
		return nil, false
	}
	return o.ProductTypeId, true
}

// HasProductTypeId returns a boolean if a field has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) HasProductTypeId() bool {
	if o != nil && !IsNil(o.ProductTypeId) {
		return true
	}

	return false
}

// SetProductTypeId gets a reference to the given int64 and assigns it to the ProductTypeId field.
func (o *CharactersCharacterIdIndustryJobsGetInner) SetProductTypeId(v int64) {
	o.ProductTypeId = &v
}

// GetRuns returns the Runs field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetRuns() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Runs
}

// GetRunsOk returns a tuple with the Runs field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetRunsOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Runs, true
}

// SetRuns sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetRuns(v int64) {
	o.Runs = v
}

// GetStartDate returns the StartDate field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetStartDate() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.StartDate
}

// GetStartDateOk returns a tuple with the StartDate field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetStartDateOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.StartDate, true
}

// SetStartDate sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetStartDate(v time.Time) {
	o.StartDate = v
}

// GetStationId returns the StationId field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetStationId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.StationId
}

// GetStationIdOk returns a tuple with the StationId field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetStationIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.StationId, true
}

// SetStationId sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetStationId(v int64) {
	o.StationId = v
}

// GetStatus returns the Status field value
func (o *CharactersCharacterIdIndustryJobsGetInner) GetStatus() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Status
}

// GetStatusOk returns a tuple with the Status field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetStatusOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Status, true
}

// SetStatus sets field value
func (o *CharactersCharacterIdIndustryJobsGetInner) SetStatus(v string) {
	o.Status = v
}

// GetSuccessfulRuns returns the SuccessfulRuns field value if set, zero value otherwise.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetSuccessfulRuns() int64 {
	if o == nil || IsNil(o.SuccessfulRuns) {
		var ret int64
		return ret
	}
	return *o.SuccessfulRuns
}

// GetSuccessfulRunsOk returns a tuple with the SuccessfulRuns field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) GetSuccessfulRunsOk() (*int64, bool) {
	if o == nil || IsNil(o.SuccessfulRuns) {
		return nil, false
	}
	return o.SuccessfulRuns, true
}

// HasSuccessfulRuns returns a boolean if a field has been set.
func (o *CharactersCharacterIdIndustryJobsGetInner) HasSuccessfulRuns() bool {
	if o != nil && !IsNil(o.SuccessfulRuns) {
		return true
	}

	return false
}

// SetSuccessfulRuns gets a reference to the given int64 and assigns it to the SuccessfulRuns field.
func (o *CharactersCharacterIdIndustryJobsGetInner) SetSuccessfulRuns(v int64) {
	o.SuccessfulRuns = &v
}

func (o CharactersCharacterIdIndustryJobsGetInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CharactersCharacterIdIndustryJobsGetInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["activity_id"] = o.ActivityId
	toSerialize["blueprint_id"] = o.BlueprintId
	toSerialize["blueprint_location_id"] = o.BlueprintLocationId
	toSerialize["blueprint_type_id"] = o.BlueprintTypeId
	if !IsNil(o.CompletedCharacterId) {
		toSerialize["completed_character_id"] = o.CompletedCharacterId
	}
	if !IsNil(o.CompletedDate) {
		toSerialize["completed_date"] = o.CompletedDate
	}
	if !IsNil(o.Cost) {
		toSerialize["cost"] = o.Cost
	}
	toSerialize["duration"] = o.Duration
	toSerialize["end_date"] = o.EndDate
	toSerialize["facility_id"] = o.FacilityId
	toSerialize["installer_id"] = o.InstallerId
	toSerialize["job_id"] = o.JobId
	if !IsNil(o.LicensedRuns) {
		toSerialize["licensed_runs"] = o.LicensedRuns
	}
	toSerialize["output_location_id"] = o.OutputLocationId
	if !IsNil(o.PauseDate) {
		toSerialize["pause_date"] = o.PauseDate
	}
	if !IsNil(o.Probability) {
		toSerialize["probability"] = o.Probability
	}
	if !IsNil(o.ProductTypeId) {
		toSerialize["product_type_id"] = o.ProductTypeId
	}
	toSerialize["runs"] = o.Runs
	toSerialize["start_date"] = o.StartDate
	toSerialize["station_id"] = o.StationId
	toSerialize["status"] = o.Status
	if !IsNil(o.SuccessfulRuns) {
		toSerialize["successful_runs"] = o.SuccessfulRuns
	}
	return toSerialize, nil
}

func (o *CharactersCharacterIdIndustryJobsGetInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"activity_id",
		"blueprint_id",
		"blueprint_location_id",
		"blueprint_type_id",
		"duration",
		"end_date",
		"facility_id",
		"installer_id",
		"job_id",
		"output_location_id",
		"runs",
		"start_date",
		"station_id",
		"status",
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

	varCharactersCharacterIdIndustryJobsGetInner := _CharactersCharacterIdIndustryJobsGetInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCharactersCharacterIdIndustryJobsGetInner)

	if err != nil {
		return err
	}

	*o = CharactersCharacterIdIndustryJobsGetInner(varCharactersCharacterIdIndustryJobsGetInner)

	return err
}

type NullableCharactersCharacterIdIndustryJobsGetInner struct {
	value *CharactersCharacterIdIndustryJobsGetInner
	isSet bool
}

func (v NullableCharactersCharacterIdIndustryJobsGetInner) Get() *CharactersCharacterIdIndustryJobsGetInner {
	return v.value
}

func (v *NullableCharactersCharacterIdIndustryJobsGetInner) Set(val *CharactersCharacterIdIndustryJobsGetInner) {
	v.value = val
	v.isSet = true
}

func (v NullableCharactersCharacterIdIndustryJobsGetInner) IsSet() bool {
	return v.isSet
}

func (v *NullableCharactersCharacterIdIndustryJobsGetInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCharactersCharacterIdIndustryJobsGetInner(val *CharactersCharacterIdIndustryJobsGetInner) *NullableCharactersCharacterIdIndustryJobsGetInner {
	return &NullableCharactersCharacterIdIndustryJobsGetInner{value: val, isSet: true}
}

func (v NullableCharactersCharacterIdIndustryJobsGetInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCharactersCharacterIdIndustryJobsGetInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


