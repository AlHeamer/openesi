package sde

import (
	"strconv"
	"strings"
)

/*
`groupID` int(11) NOT NULL,
`categoryID` int(11) DEFAULT NULL,
`iconID` int(11) DEFAULT NULL,
`anchorable` tinyint(1) DEFAULT NULL,
`anchored` tinyint(1) DEFAULT NULL,
`fittableNonSingleton` tinyint(1) DEFAULT NULL,
`published` tinyint(1) DEFAULT NULL,
`useBasePrice` tinyint(1) DEFAULT NULL,
`groupName` varchar(100) DEFAULT NULL,
*/
const GroupColumns = `groupID,categoryID,iconID,anchorable,anchored,fittableNonSingleton,published,useBasePrice,groupName`

/*
	"_key": 0,
	"categoryID": 0,
	"iconID": 0,
	"anchorable": false,
	"anchored": false,
	"fittableNonSingleton": false,
	"published": false,
	"useBasePrice": false
	"name": {}
*/

type Group struct {
	ID                   int64             `json:"_key"`
	CategoryID           int64             `json:"categoryID,omitzero"`
	IconID               int64             `json:"iconID,omitzero"`
	Anchorable           bool              `json:"anchorable,omitzero"`
	Anchored             bool              `json:"anchored,omitzero"`
	FittableNonSingleton bool              `json:"fittableNonSingleton,omitzero"`
	Published            bool              `json:"published,omitzero"`
	UseBasePrice         bool              `json:"useBasePrice,omitzero"`
	Name                 map[string]string `json:"name"`
}

func (s *Group) ToSqlValues(lang string, vals *strings.Builder) {
	vals.WriteString(strconv.FormatInt(s.ID, 10))
	vals.WriteString(nullableInt(s.CategoryID) + ",")
	vals.WriteString("'" + strings.ReplaceAll(s.Name[lang], "'", "''") + "',")
	vals.WriteString(nullableInt(s.IconID) + ",")
	vals.WriteString(nullableBool(s.UseBasePrice) + ",")
	vals.WriteString(nullableBool(s.Anchored) + ",")
	vals.WriteString(nullableBool(s.Anchorable) + ",")
	vals.WriteString(nullableBool(s.FittableNonSingleton) + ",")
	vals.WriteString(nullableBool(s.Published) + ")")
}
