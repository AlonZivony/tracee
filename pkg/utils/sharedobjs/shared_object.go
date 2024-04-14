package sharedobjs

import "debug/elf"

// ObjID is the unique identification of a SO in the system
type ObjID struct {
	Inode  uint64
	Device uint32
	Ctime  uint64
}

// ObjInfo is the information of an SO needed to examine it
type ObjInfo struct {
	Id      ObjID
	Path    string
	MountNS int
}

type DynamicSymbolsLoader interface {
	GetDynamicSymbols(info ObjInfo) (map[string]DynamicSymbol, error)
	GetExportedSymbols(info ObjInfo) (map[string]DynamicSymbol, error)
	GetImportedSymbols(info ObjInfo) (map[string]DynamicSymbol, error)
}

type dynamicSymbols struct {
	Exported map[string]DynamicSymbol
	Imported map[string]DynamicSymbol
}

func newSOSymbols() dynamicSymbols {
	return dynamicSymbols{
		Exported: make(map[string]DynamicSymbol),
		Imported: make(map[string]DynamicSymbol),
	}
}

// This const is missing from the standard libarary so it is added here.
// The `String()` method won't work for it because of it, hope it will be added soon.
const STT_GNU_IFUNC elf.SymType = 10

type DynamicSymbol struct {
	name       string
	symbolType elf.SymType
}

func (ds DynamicSymbol) GetName() string {
	return ds.name
}

func (ds DynamicSymbol) GetType() elf.SymType {
	return ds.symbolType
}
