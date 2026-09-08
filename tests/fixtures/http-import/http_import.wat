(component
  (import "wasi:http/outgoing-handler@0.2.0"
    (instance
      (export "handle"
        (func (param "request" u32) (param "options" u32) (result u32))
      )
    )
  )
  (core module $m
    (func (export "probe"))
  )
  (core instance $i (instantiate $m))
  (func (export "probe") (canon lift (core func $i "probe")))
)
