package proctree

func (t *threadNode) fillGeneralInfo(ns NamespacesIDs, defaultExitTime timestamp) {
	if t.Status.Contains(uint32(generalCreated)) {
		return
	}
	t.Mutex.Lock()
	t.Namespaces = ns
	if t.Status.Contains(uint32(exited)) {
		t.exitTime = defaultExitTime
	}
	t.Status.Add(uint32(generalCreated))
	t.Mutex.Unlock()
}

func (t *threadNode) fillForkInfo(forkTime timestamp) {
	if t.Status.Contains(uint32(forked)) {
		return
	}
	t.Mutex.Lock()
	t.forkTime = forkTime
	t.Status.Add(uint32(forked))
	t.Mutex.Unlock()
}

func (t *threadNode) fillExitInfo(exitTime timestamp) {
	if t.Status.Contains(uint32(exited)) {
		return
	}
	t.Mutex.Lock()
	t.exitTime = exitTime
	t.Status.Add(uint32(exited))
	t.Mutex.Unlock()
}

func (t *threadNode) fillDefaultExitInfo(defaultExitTime timestamp) {
	if t.Status.Contains(uint32(exited)) {
		return
	}
	t.Mutex.Lock()
	t.exitTime = defaultExitTime
	t.Mutex.Unlock()
}

func (t *threadNode) disconnectFromProcess() {
	t.Mutex.Lock()
	t.Process = nil
	t.Mutex.Unlock()
}
