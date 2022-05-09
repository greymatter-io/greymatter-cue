package main

import (
	"fmt"
	"go/ast"
	"log"
	"os"
	"path/filepath"
	"strings"

	ta "github.com/bcmendoza/toast"
	"golang.org/x/tools/go/packages"
)

var (
	filterDirPath = "/filters"
)

// Generates CUE schemas for Grey Matter filters fetched from the gm-proxy repo
func main() {
	wd, _ := os.Getwd()

	// Identify the absolute path to the filter directory to instruct the Go package loader to load packages directly from the path instead of from the GOPATH.
	// i.e. /home/you/go/src/github.com/greymatter-io/greymatter-cue/_gen/filters
	absDirPath := filepath.Join(wd, filterDirPath)

	// Load the Go packages in the filter subdirectories
	cfg := &packages.Config{
		Dir:  absDirPath,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax,
	}
	pkgs, err := packages.Load(cfg, absDirPath+"/...")
	if err != nil {
		log.Fatal(err)
	}

	// Prepare transform options to apply on each ToAST File.
	var opts []ta.Option
	for _, t := range transforms {
		opts = append(opts, ta.WithTransform(t))
	}

	for _, pkg := range pkgs {

		// Use the subdirectory name as the CUE package name, rather than "proto".
		cuePkgName := filepath.Base(pkg.PkgPath)

		// Determine the destination dir path from the CUE package name.
		destDirPath, _ := filepath.Abs(filepath.Join("../greymatter.io/api", filterDirPath, cuePkgName))

		for i := 0; i < len(pkg.Syntax); i++ {
			outputFilePath := filepath.Join(destDirPath, strings.Replace(filepath.Base(pkg.CompiledGoFiles[i]), ".pb.go", ".cue", 1))
			fmt.Println("Generating", outputFilePath)

			// Generate a ToAST File from a .pb.go file.
			file := ta.NewFile(pkg.Syntax[i], append(opts, ta.WithCUEPackageName(cuePkgName))...)

			// Place the file in the respective type of filter dir
			if err := os.WriteFile(outputFilePath, []byte(file.CUE()), 0644); err != nil {
				log.Fatal(err)
			}
		}
	}
}

var transforms = []ta.Transform{
	// Exclude all unused explicit imports, or ones named 'protoimpl'
	&ta.ExcludeImport{
		Match: func(i ta.Import) bool {
			return i.Name == "_" || i.Name == "protoimpl"
		},
	},
	&ta.ExcludeType{
		Match: func(t ta.Type) bool {
			name := t.GetName()
			// Exclude all unused explicit types.
			if name == "_" {
				return true
			}
			// Exclude all unexported types.
			n := string(name[0])
			return n != strings.ToUpper(n)
		},
	},
	&ta.ExcludeField{
		Match: func(field *ta.Field) bool {
			// Exclude all fields without a json tag (or an unnamed json tag)
			if len(field.Tags) == 0 {
				return true
			}
			if tag, ok := field.Tags["json"]; ok {
				if tag[0] == "-" {
					return true
				}
			}
			return false
		},
	},
	&ta.ModifyField{
		Apply: func(f *ta.Field) *ta.Field {
			// Remove all unnecessary non-json tags.
			if jsonTags, ok := f.Tags["json"]; ok {
				f.Tags = map[string][]string{"json": jsonTags}
				return f
			}
			// Also, where needed, inject json tags with the given protobuf name.
			if protobufTags, ok := f.Tags["protobuf"]; ok {
				for _, tag := range protobufTags {
					if strings.HasPrefix(tag, "name=") {
						f.Tags = map[string][]string{"json": {tag[5:], "omitempty"}}
						return f
					}
				}
			}
			return f
		},
	},
	&ta.GenEnumTypeTransform{
		// Parse the generated pb.go docstrings to get enum types.
		// This will be used by toast to generate enum types properly expressed in CUE.
		Generate: func(docs string, spec *ast.ValueSpec) *ta.PromoteToEnumType {
			etName := strings.Replace(docs, "// Enum value maps for ", "", 1)
			if len(etName) == len(docs) ||
				len(spec.Names) < 1 ||
				!strings.HasSuffix(spec.Names[0].Name, "_name") ||
				len(spec.Values) < 1 {
				return nil
			}

			et := &ta.EnumType{
				Name: etName[:len(etName)-2],
			}
			for _, expr := range spec.Values[0].(*ast.CompositeLit).Elts {
				v := expr.(*ast.KeyValueExpr).Value.(*ast.BasicLit).Value
				et.Values = append(et.Values, strings.Replace(v, "\"", "", -1))
			}

			return &ta.PromoteToEnumType{
				Apply: func(pt *ta.PlainType) *ta.EnumType {
					if pt.Name != et.Name {
						return nil
					}
					et.Docs = pt.Docs
					return et
				},
			}
		},
	},
}
