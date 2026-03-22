package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/AlHeamer/sde"
)

const (
	argKeycheck = "keycheck"
)

var typeMap = map[string]reflect.Type{
	"_sde":                        reflect.TypeFor[sde.Meta](),
	"agentTypes":                  reflect.TypeFor[sde.AgentType](),
	"agentsInSpace":               reflect.TypeFor[sde.AgentInSpace](),
	"ancestries":                  reflect.TypeFor[sde.Ancestry](),
	"bloodlines":                  reflect.TypeFor[sde.Bloodline](),
	"blueprints":                  reflect.TypeFor[sde.Blueprint](),
	"categories":                  reflect.TypeFor[sde.Category](),
	"certificates":                reflect.TypeFor[sde.Certificate](),
	"characterAttributes":         reflect.TypeFor[sde.CharacterAttribute](),
	"contrabandTypes":             reflect.TypeFor[sde.ContrabandType](),
	"controlTowerResources":       reflect.TypeFor[sde.ControlTowerResource](),
	"corporationActivities":       reflect.TypeFor[sde.CorporationActivity](),
	"dbuffCollections":            reflect.TypeFor[sde.DbuffCollection](),
	"dogmaAttributeCategories":    reflect.TypeFor[sde.DogmaAttributeCategory](),
	"dogmaAttributes":             reflect.TypeFor[sde.DogmaAttribute](),
	"dogmaEffects":                reflect.TypeFor[sde.DogmaEffect](),
	"dogmaUnits":                  reflect.TypeFor[sde.DogmaUnit](),
	"dynamicItemAttributes":       reflect.TypeFor[sde.DynamicItemAttribute](),
	"factions":                    reflect.TypeFor[sde.Faction](),
	"graphics":                    reflect.TypeFor[sde.Graphic](),
	"icons":                       reflect.TypeFor[sde.Icon](),
	"landmarks":                   reflect.TypeFor[sde.Landmark](),
	"mapAsteroidBelts":            reflect.TypeFor[sde.MapAsteroidBelt](),
	"mapConstellations":           reflect.TypeFor[sde.MapContellation](),
	"mapMoons":                    reflect.TypeFor[sde.MapMoon](),
	"mapPlanets":                  reflect.TypeFor[sde.MapPlanet](),
	"mapRegions":                  reflect.TypeFor[sde.MapRegion](),
	"mapSolarSystems":             reflect.TypeFor[sde.MapSolarSystem](),
	"mapStargates":                reflect.TypeFor[sde.MapStargate](),
	"mapStars":                    reflect.TypeFor[sde.MapStar](),
	"marketGroups":                reflect.TypeFor[sde.MarketGroup](),
	"masteries":                   reflect.TypeFor[sde.Mastery](),
	"mercenaryTacticalOperations": reflect.TypeFor[sde.MercenaryTacticalOperations](),
	"metaGroups":                  reflect.TypeFor[sde.MetaGroup](),
	"npcCharacters":               reflect.TypeFor[sde.NpcCharacter](),
	"npcCorporationDivisions":     reflect.TypeFor[sde.NpcCorporationDivision](),
	"npcCorporations":             reflect.TypeFor[sde.NpcCorporation](),
	"npcStations":                 reflect.TypeFor[sde.NpcStation](),
	"planetResources":             reflect.TypeFor[sde.PlanetResource](),
	"planetSchematics":            reflect.TypeFor[sde.PlanetSchematic](),
	"races":                       reflect.TypeFor[sde.Race](),
	"skinLicenses":                reflect.TypeFor[sde.SkinLicense](),
	"skinMaterials":               reflect.TypeFor[sde.SkinMaterial](),
	"skins":                       reflect.TypeFor[sde.Skin](),
	"sovereigntyUpgrades":         reflect.TypeFor[sde.SovereigntyUpgrade](),
	"stationOperations":           reflect.TypeFor[sde.StationOperation](),
	"stationServices":             reflect.TypeFor[sde.StationService](),
	"translationLanguages":        reflect.TypeFor[sde.TranslationLanguage](),
	"typeBonus":                   reflect.TypeFor[sde.TypeBonus](),
	"typeDogma":                   reflect.TypeFor[sde.TypeDogma](),
	"typeMaterials":               reflect.TypeFor[sde.TypeMaterial](),
	"groups":                      reflect.TypeFor[sde.Group](),
	"types":                       reflect.TypeFor[sde.Type](),
}

var helpKeycheck string = `The keycheck command verfifies all keys existing inside .json files also exist
in the corresponding struct.

Usage:
	` + path.Base(os.Args[0]) + ` keycheck [arguments] <directory>

Arguments are:`

func cmdKeycheck() {
	var verbose bool
	flagSet := flag.NewFlagSet("keycheck", flag.ExitOnError)
	flagSet.BoolVar(&verbose, "v", false, "print additional per-file key statistics")
	flagSet.Parse(os.Args[1:])

	if flagSet.Arg(0) == argHelp {
		usage(helpKeycheck, flagSet)
	}

	inDir := flagSet.Arg(1)
	if inDir == "" {
		usage(helpKeycheck, flagSet)
	}
	inDir = path.Clean(inDir)

	dir, err := os.ReadDir(inDir)
	if err != nil {
		log.Fatalf("error opening dir: %s", err.Error())
	}

	for _, entry := range dir {
		file, err := os.Open(path.Join(inDir, entry.Name()))
		if err != nil {
			log.Fatal(err.Error())
		}

		recursiveReadFile(file, verbose)
		file.Close()
	}
}

func recursiveReadFile(file *os.File, verbose bool) {
	stat, err := file.Stat()
	if err != nil {
		log.Println(err.Error())
		return
	}

	if stat.IsDir() {
		dirEntries, err := file.ReadDir(0)
		if err != nil {
			log.Printf("error reading dir: %s", err.Error())
			return
		}

		for _, entry := range dirEntries {
			if entry.Name()[0] == '.' {
				continue
			}

			if !strings.HasSuffix(entry.Name(), ".jsonl") {
				log.Println("non-jsonl file:", file.Name())
				continue
			}

			fh, err := os.Open(path.Join(file.Name(), entry.Name()))
			if err != nil {
				log.Println(err.Error())
				continue
			}

			recursiveReadFile(fh, verbose)
			fh.Close()
		}

		return
	}

	readFile(file, verbose)
}

func readFile(file *os.File, verbose bool) {
	base := path.Base(file.Name())
	if base[0] == '.' {
		return
	}

	if !strings.HasSuffix(base, ".jsonl") {
		log.Println("non-jsonl file:", file.Name())
		return
	}

	sb := strings.Builder{}
	sb.WriteString(base)

	rt, ok := typeMap[strings.Split(base, ".")[0]]
	if !ok {
		sb.WriteString(": no struct, skipping")
		log.Println(sb.String())
		return
	}

	j := json.NewDecoder(file)
	keyMap := make(map[string]int)
	for j.More() {
		obj := make(map[string]any)
		if err := j.Decode(&obj); err != nil {
			sb.WriteString(": error decoding json: " + err.Error())
			log.Println(sb.String())
			return
		}
		keys := maps.Keys(obj)
		for key := range keys {
			keyMap[key]++
		}
	}

	numFields := rt.NumField()
	if numFields == 0 {
		sb.WriteString(": incomplete struct")
		log.Println(sb.String())
		return
	}
	fields := make(map[string]struct{})
	for i := range numFields {
		jsonTag := rt.Field(i).Tag.Get("json")
		tags := strings.Split(jsonTag, ",")
		fields[tags[0]] = struct{}{}
		if _, ok := keyMap[tags[0]]; !ok {
			sb.WriteString("\n\tstruct extra tag: " + tags[0])
		}
	}

	var s int
	keys := slices.Collect(maps.Keys(keyMap))
	slices.Sort(keys)
	for _, key := range keys {
		s = max(s, len(key))
	}
	s += 3

	ob := strings.Builder{}
	if verbose {
		ob.WriteString("\n\tKey Count:\n")
	}
	for _, key := range keys {
		if verbose {
			ob.WriteString(fmt.Sprintf("\t\t%*s %d\n", -s, key, keyMap[key]))
		}
		if _, ok := fields[key]; !ok {
			sb.WriteString("\n\tstruct missing tag: " + key)
		}
	}

	log.Print(sb.String() + ob.String())
}
