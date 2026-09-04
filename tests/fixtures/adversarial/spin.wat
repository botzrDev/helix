;; RT-5: guest that never yields (infinite loop).
(component
  (core module $m
    (func (export "run")
      (loop $l (br $l)))
  )
  (core instance $i (instantiate $m))
  (func (export "run") (canon lift (core func $i "run")))
)
