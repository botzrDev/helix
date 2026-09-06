(component
  (type $ie (variant (case "invalid-input" string) (case "capability-denied" string) (case "internal" string)))
  (type $sig (record (field "name" string) (field "version" string) (field "input-schema" string) (field "output-schema" string)))
  (core module $m
    (func $sig (result i32) unreachable)
    (func $invoke (param i32 i32) (result i32)
      (loop $l (br $l)))
    (memory (export "memory") 1)
    (func $cabi_realloc (param i32 i32 i32 i32) (result i32) (local.get 0))
    (export "cabi_realloc" (func $cabi_realloc))
    (export "signature" (func $sig))
    (export "invoke" (func $invoke))
  )
  (core instance $i (instantiate $m))
  ;; Too minimal for real component ABI — use cargo-component instead
)
