+++
title = "TEST PAGE"
slug = "test"
date = 2021-03-30
+++

# Heading1
## Heading2
### Heading3
#### Heading4


```rust
// comment
pub fn test(a: u64) -> bool {
    return false;
}
```

> this is some quoted text! test

$$
f(\relax{x}) = \int_{-\infty}^\infty
    f\hat(\xi)\,e^{2 \pi i \xi x}
    \,d\xi 
$$


```py
# test
def test(a):
    return sum(a)

```


> some
> more
> quoted text!
>
> with empty lines

this is `some` text with `inline` code.

1. first item
2. second item
   - sub item
   - sub item
   - sub item
  
[A wild external link appears!](https://news.ycombinator.com)

[internal link](@/test/index.md)

[Link to heading 3](#heading3)


| Tables        | Are           | Cool  |
| ------------- |:-------------:| -----:|
| col 3 is      | right-aligned | $1600 |
| col 2 is      | centered      |   $12 |
| zebra stripes | are neat      |    $1 |


---

horizontal rules

---

Some text before an image.

{{ img(src="Lena.png", caption="
Image caption.
[Lena](https://en.wikipedia.org/wiki/Lenna).
") }}

Normal Paragraph after image.