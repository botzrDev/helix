(component
  (import "wasi:sockets/instance-network@0.2.0"
    (instance
      (export "instance-network" (func (result u32)))
    )
  )
  (core module $m
    (func (export "probe"))
  )
  (core instance $i (instantiate $m))
  (func (export "probe") (canon lift (core func $i "probe")))
)
