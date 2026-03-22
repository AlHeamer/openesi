package sde

import (
	"strconv"
	"strings"
)

type Type struct {
	BasePrice             float64           `json:"basePrice,omitempty"`
	Capacity              float64           `json:"capacity,omitempty"`
	FactionID             int64             `json:"factionID,omitempty"`
	GraphicID             int64             `json:"graphicID,omitempty"`
	GroupID               int64             `json:"groupID"`
	IconID                int64             `json:"iconID,omitempty"`
	MarketGroupID         int64             `json:"marketGroupID,omitempty"`
	Mass                  float64           `json:"mass,omitempty"`
	MetaGroupID           int64             `json:"metaGroupID,omitempty"`
	PortionSize           int64             `json:"portionSize,omitempty"`
	RaceID                int64             `json:"raceID,omitempty"`
	Radius                float64           `json:"radius,omitempty"`
	SoundID               int64             `json:"soundID,omitempty"`
	TypeID                int64             `json:"_key"`
	VariationParentTypeID int64             `json:"variationParentTypeID,omitempty"`
	Volume                float64           `json:"volume,omitempty"`
	Description           map[string]string `json:"description"`
	Name                  map[string]string `json:"name"`
	Published             bool              `json:"published"`
}

func (s *Type) ToSqlValues(lang string, vals *strings.Builder) {
	var (
		typeName     = strings.ReplaceAll(s.Name[lang], "'", "''")        // escape single quotes in names
		description1 = strings.ReplaceAll(s.Description[lang], "'", "''") // escape single quotes in descriptions
		description  = strings.ReplaceAll(description1, "\n", "\\r\\n")   // replace string \n with real \r\n
	)

	vals.WriteString("(" + strconv.FormatInt(s.TypeID, 10) + ",")
	vals.WriteString(nullableInt(s.GroupID) + ",")
	vals.WriteString("'" + typeName + "',")
	vals.WriteString("'" + description + "',")
	vals.WriteString(nullableFloat(s.Mass) + ",")
	vals.WriteString(nullableFloat(s.Volume) + ",")
	vals.WriteString(nullableFloat(s.Capacity) + ",")
	vals.WriteString(nullableInt(s.PortionSize) + ",")
	vals.WriteString(nullableInt(s.RaceID) + ",")
	vals.WriteString(nullableFloat(s.BasePrice) + ",")
	vals.WriteString(nullableBool(s.Published) + ",")
	vals.WriteString(nullableInt(s.MarketGroupID) + ",")
	vals.WriteString(nullableInt(s.IconID) + ",")
	vals.WriteString(nullableInt(s.SoundID) + ",")
	vals.WriteString(nullableInt(s.GraphicID) + ")")
}
