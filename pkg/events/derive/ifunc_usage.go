package derive

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/sharedobjs"
	"github.com/aquasecurity/tracee/types/trace"
	lru "github.com/hashicorp/golang-lru/v2"
)

func IFuncLoaded(
	soLoader sharedobjs.DynamicSymbolsLoader,
) DeriveFunction {

	gen := initifuncSymbolsLoadedGenerator(soLoader)

	return deriveSingleEvent(events.SymbolsLoaded, gen.deriveArgs)
}

// ifuncSymbolsLoadedGenerator is responsible of generating event if shared object loaded to a
// process export one or more from given watched symbols.
type ifuncSymbolsLoadedGenerator struct {
	soLoader       sharedobjs.DynamicSymbolsLoader
	returnedErrors map[string]bool
	libsCache      *lru.Cache[sharedobjs.ObjID, []string]
}

func initifuncSymbolsLoadedGenerator(
	soLoader sharedobjs.DynamicSymbolsLoader,
) *ifuncSymbolsLoadedGenerator {
	cacheLRU, _ := lru.New[sharedobjs.ObjID, []string](10240)

	return &ifuncSymbolsLoadedGenerator{
		soLoader:       soLoader,
		returnedErrors: make(map[string]bool),
		libsCache:      cacheLRU,
	}
}

func (symbsLoadedGen *ifuncSymbolsLoadedGenerator) deriveArgs(
	event trace.Event,
) (
	[]interface{}, error,
) {
	loadingObjectInfo, err := getSharedObjectInfo(event)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	matchedSyms, ok := symbsLoadedGen.getSymbolsFromCache(loadingObjectInfo.Id)
	if ok {
		if len(matchedSyms) > 0 {
			hash, _ := parse.ArgVal[string](event.Args, "sha256")
			return []interface{}{loadingObjectInfo.Path, matchedSyms, hash}, nil
		}
		return nil, nil
	}

	soSyms, err := symbsLoadedGen.soLoader.GetExportedSymbols(loadingObjectInfo)
	// This error happens frequently in some environments, so we need to silence it to reduce spam.
	// Either way, this is not a critical error so we don't return it.
	if err != nil {
		// TODO: rate limit frequent errors for overloaded envs
		_, ok := symbsLoadedGen.returnedErrors[err.Error()]
		if !ok {
			symbsLoadedGen.returnedErrors[err.Error()] = true
			logger.Warnw("symbols_loaded", "object loaded", loadingObjectInfo, "error", err.Error())
		} else {
			logger.Debugw("symbols_loaded", "object loaded", loadingObjectInfo, "error", err.Error())
		}
		return nil, nil
	}

	var ifuncSymbols = filterIfuncSymbols(soSyms)

	symbsLoadedGen.libsCache.Add(loadingObjectInfo.Id, ifuncSymbols)
	if len(ifuncSymbols) > 0 {
		hash, _ := parse.ArgVal[string](event.Args, "sha256")
		return []interface{}{loadingObjectInfo.Path, ifuncSymbols, hash}, nil
	}

	return nil, nil
}

func filterIfuncSymbols(symbols map[string]sharedobjs.DynamicSymbol) []string {
	var ifuncSymbols []string
	for symbolName, symbol := range symbols {
		if symbol.GetType() == sharedobjs.STT_GNU_IFUNC {
			ifuncSymbols = append(ifuncSymbols, symbolName)
		}
	}
	return ifuncSymbols
}

// getSymbolsFromCache query the cache for check results of specified object.
// Return the watched symbols found in the object, and if it was found in the cache.
func (symbsLoadedGen *ifuncSymbolsLoadedGenerator) getSymbolsFromCache(id sharedobjs.ObjID) ([]string, bool) {
	return symbsLoadedGen.libsCache.Get(id)
}
