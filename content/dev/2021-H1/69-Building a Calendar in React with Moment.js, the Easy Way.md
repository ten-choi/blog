---
title: "Building a Calendar in React with Moment.js, the Easy Way"
labels: ["TS","JS","react","react.js","Archive"]
published: true
date: 2021-01-02T16:27:39+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 69
tistoryUrl: "https://yeolceo.tistory.com/69"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react.js","react","react"]
tistoryPostedAt: "2021-01-02 16:27:39"
language: en
bloggerPostId: "4230238212018405237"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_5.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_6.webp)

This time, we're going to build calendar logic using **React**.

Keep in mind that the goal is to show the structure, not to make the finished product pretty!!

### \- What Is Moment.js?

It's a library that makes it easy to manipulate dates in **JavaScript**.

(Checking the official site will help your learning even more.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img.webp)

### \- Using Moment.js in React.js

First, create a React project with **npx create-react-app \[project-name\]**.

(If you already have a project, that works too.)

**moment.js** is the core library we'll use to build the calendar.

Install it from CMD with this command:   npm install moment --save

Once the project is created, clean up **App.js** like below.

I used **moment.js** with **today.format** to display the current year and month.

```html
import './App.css';
import {useState} from 'react';
import moment from 'moment';

const App =()=>{

  const [getMoment, setMoment]=useState(moment());     
  const today = getMoment;    // today == moment()

  return(
    <div className="App">

        <div className="control">
          <button>Prev month</button>
          <span>{today.format('YYYY / MM')}</span>   // YYYY is the year, MM is the month.
          <button>Next month</button>
        </div>
        <table>
          <tbody>

          </tbody>
        </table>
    </div>
  );
}
export default App;
```

You should see a screen like the one below. **moment()** is initialized to the current date when you create it.

That's a simple look at how to use the library.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_1.webp)

If you look at the site, you'll find how to use **moment()**.

**subtract** subtracts and **add** adds. You pick the date unit you want and add or subtract it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_2.webp)

So I used **useState** to make the date change by month, as below.

**clone()** means a new object is returned instead of the original **moment**.

```html
<button onClick={()=>{ setMoment(getMoment.clone().subtract(1, 'month')) }} >Prev month</button>
          <span>{today.format('YYYY / MM')}</span>
          <button onClick={()=>{ setMoment(getMoment.clone().add(1, 'month')) }} >Next month</button>
```

Click around and you'll see the date change.

### \- Building the Calendar

First, let's set up the first and last weeks.

firstWeek is the week() in which the month starts, via startOf('month').

lastWeek is the week() in which the month ends, via endOf('month').

Now we know the first and last weeks of the month.

```html
const App =()=>{

  const [getMoment, setMoment]=useState(moment());

  const today = getMoment;
  const firstWeek = today.clone().startOf('month').week();
  const lastWeek = today.clone().endOf('month').week() === 1 ? 53 : today.clone().endOf('month').week();
```

Look at the condition used in **lastWeek**: a year has **52** weeks plus a few extra days, and a calendar needs to

show those as week 53!! But **moment()** shows that as **1**, the first week of next year,

so if the last week is **1**, we show it as **53** instead.

In **React**, if you render an array like below, it renders every element in the array,

```html
const arr = [1, 2, 3, 4, 5];

  return (
    <div className="App">
        <table>
          <tbody>
            {arr}  // 12345 is shown on the page.
          </tbody>
        </table>
    </div>
  );
```

so we'll build on that and put a table row, **<tr></tr>**, in each array element to render the calendar.

Now that you've seen how arrays render, you can build the table easily with code like this.

A loop runs once for each week in the month and adds the table content to the array.

```html
const calendarArr=()=>{

      let result = [];
      let week = firstWeek;
      for ( week; week <= lastWeek; week++) {
        result = result.concat(
          <tr key={week}>

          </tr>);
      }
      return result;
    }

  return (
    <div className="App">

        <div className="control">
          <button onClick={()=>{ setMoment(getMoment.clone().subtract(1, 'month')) }} >Prev month</button>
          <span>{today.format('YYYY / MM')}</span>
          <button onClick={()=>{ setMoment(getMoment.clone().add(1, 'month')) }} >Next month</button>
        </div>
        <table>
          <tbody>
            {calendarArr()}
          </tbody>
        </table>
    </div>
  );
}
export default App;
```

With **week** set up, let's set up **days**. Loop over 7 days for each **week** and you'll get output like below.

We use **index** to add +0 through +6 to the starting day of each week!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_3.webp)

```html
<tr key={week}>
            {
              Array(7).fill(0).map((data, index) => {
                let days = today.clone().startOf('year').week(week).startOf('week').add(index, 'day');

                return(
                    <td key={index}  >
                      <span>{days.format('D')}</span>
                    </td>
                );

              })
            }
          </tr>
```

**\- Here comes the important part -**

Since **moment()** is based on the current date, it might seem like you don't need **startOf('year')**, but you do!!

I mentioned that **moment()** is initialized to the current date.

When we hit the week-53 case we handled above, **moment()** returns 1, which is why we changed it to 53.

The **today** variable used in **days** can run into the same problem.

It could render week 53 as next year and give us the wrong result, so we always pin the year.

**Almost there... hang in there!!!**

When we look at a calendar, it usually also shows days that aren't in the current month.

And on a computer calendar, highlighting today is a given. Let's code it.

```html
<tr key={week}>
            {
              Array(7).fill(0).map((data, index) => {
                let days = today.clone().startOf('year').week(week).startOf('week').add(index, 'day');

                if(moment().format('YYYYMMDD') === days.format('YYYYMMDD')){
                  return(
                      <td key={index} style={{backgroundColor:'red'}} >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }else if(days.format('MM') !== today.format('MM')){
                  return(
                      <td key={index} style={{backgroundColor:'gray'}} >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }else{
                  return(
                      <td key={index}  >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }
              })
            }
          </tr>
```

Using **moment().format** for the current date, the background is **RED** if the day is today,

**GRAY** if the day isn't in that month, and uncolored otherwise.

When you're done, your code should look like this. I've included the CSS as well.

**App.js**

```html
import './App.css';
import {useState} from 'react';
import moment from 'moment';

const App =()=>{

  const [getMoment, setMoment]=useState(moment());

  const today = getMoment;
  const firstWeek = today.clone().startOf('month').week();
  const lastWeek = today.clone().endOf('month').week() === 1 ? 53 : today.clone().endOf('month').week();

    const calendarArr=()=>{

      let result = [];
      let week = firstWeek;
      for ( week; week <= lastWeek; week++) {
        result = result.concat(
          <tr key={week}>
            {
              Array(7).fill(0).map((data, index) => {
                let days = today.clone().startOf('year').week(week).startOf('week').add(index, 'day'); // 'd' works too, but 'day' is more readable

                if(moment().format('YYYYMMDD') === days.format('YYYYMMDD')){
                  return(
                      <td key={index} style={{backgroundColor:'red'}} >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }else if(days.format('MM') !== today.format('MM')){
                  return(
                      <td key={index} style={{backgroundColor:'gray'}} >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }else{
                  return(
                      <td key={index}  >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }
              })
            }
          </tr>
        );
      }
      return result;
    }

  return (
    <div className="App">

        <div className="control">
          <button onClick={()=>{ setMoment(getMoment.clone().subtract(1, 'month')) }} >Prev month</button>
          <span>{today.format('YYYY / MM')}</span>
          <button onClick={()=>{ setMoment(getMoment.clone().add(1, 'month')) }} >Next month</button>
        </div>
        <table>
          <tbody>
            {calendarArr()}
          </tbody>
        </table>
    </div>
  );
}
export default App;
```

**App.css**

```html
html, body {
  height: 100%;
}

 .App {
  height:100vh;
  width:100vw;
  font-size: 1.5vh;
  display: flex;      /* display must be flex so you can choose a direction below */
  flex-direction: column;   /* lays out the child tags vertically */
  align-items: center;      /* centers horizontally */
  justify-content: center;  /* centers vertically */

}

.App .control{
  display: flex;
  flex-direction: row;
}
.App table{
  display:flex;
  width:50vw;
  height:50vh;
}
.App table tbody{
  display:flex;
  flex-direction: column;
}
.App tr{
    display:flex;
    flex-direction: row;
}
.App td{
    display:flex;
    border:1px solid gray;
    width:5vw;
    height:5vh;
}
.App td span{
    display: flex;
    justify-content: flex-start;
    align-items: flex-start;
}
```

Does your screen look like the one below, with the buttons working?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_4.webp)

Congratulations. Style the **UI** separately and you'll have a much prettier calendar, and with a little more work

you can build your own custom calendar with all kinds of features. Happy coding!!
