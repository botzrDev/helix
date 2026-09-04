;; RT-10 / HLX-29: trivial guest that returns immediately (no imports).
(component
  (core module $m
    (func (export "run")
      (nop))
  )
  (core instance $i (instantiate $m))
  (func (export "run") (canon lift (core func $i "run")))
)
