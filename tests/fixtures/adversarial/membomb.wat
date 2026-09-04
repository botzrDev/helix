;; RT-6: grow linear memory forever until limiter traps.
(component
  (core module $m
    (memory (export "memory") 1)
    (func (export "run")
      (loop $l
        (drop (memory.grow (i32.const 1)))
        (br $l)))
  )
  (core instance $i (instantiate $m))
  (alias core export $i "memory" (core memory $mem))
  (func (export "run") (canon lift (core func $i "run")))
)
