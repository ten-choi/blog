---
title: "React Inputs, Explained Simply"
labels: ["TS","JS","react","input","Archive"]
published: true
date: 2020-08-10T13:24:27+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 37
tistoryUrl: "https://yeolceo.tistory.com/37"
tistoryCategory: "TS, JS/react"
tistoryTags: ["input","react","input"]
tistoryPostedAt: "2020-08-10 13:24:27"
language: en
bloggerPostId: "8692634725354448682"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/37/img.webp)

## **\- What Is an Input?**

      An HTML tag that accepts keyboard input.

## **\- Using It in JSX**

To change an input's value and know what it changed to, you need a few steps.

In the example below, the input's e.target.value picks up what was typed, and at the same time

handleChange puts that value into the value field in state and updates it immediately

with setState.

```html
import React  from 'react'

export default class App extends React.Component {
  state = {
    value:''
  }
  handleChange = (e) => {
    this.setState({
      value: e.target.value
    });
  }
  render() {
    return (
        <>
        <input
          placeholder="input start"
          value={this.state.value}
          onChange={this.handleChange}
        />
      <div>{this.state.value}</div>
        </>
    );
  }
}
```

This is very simple, but it's one-to-one. So if you have several inputs,

you might end up with value1, value2, and so on. That gets tedious fast.

Instead, you can have a single handler cover any number of inputs.

```html
import React  from 'react'

export default class App extends React.Component {
  state = {
    name1: '',
   	name2: ''
  }
  handleChange = (e) => {
    this.setState({
      [e.target.name]: e.target.value
    });
  }
  render() {
    return (
	<>
        <input
          placeholder="name1"
          value={this.state.name1}
          onChange={this.handleChange}
          name="name1"
        />
        <input
          placeholder="name2"
          value={this.state.name2}
          onChange={this.handleChange}
          name="name2"
        />
        <div>{this.state.name1} {this.state.name2}</div>
    </>
    );
  }
}
```

"If you wrap a key in \[ \], the actual value the reference inside points to is used as the key."

That line comes from a React book.

"Keys help React identify which items have changed, are added, or are removed. Keys should be given to the elements inside the array to give the elements a stable identity."

And that line is from the official React docs (though it seems to be there because of map...).

If you think of e.target (or e) as the key that helps identify which item is being changed, added, or removed,

the explanation fits. Wrapping it in \[\] means the key isn't the literal text you typed,

but the value that reference actually points to on that tag. I may be glossing over some fine details, but that's the idea.

I hope this made it easy to understand.
