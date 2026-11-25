---
title: "[ Resume ] How to Show Notion Date Differences in Years, Months, and Days"
labels: ["Branding","Resume","Formula","notion","Archive"]
published: true
date: 2023-07-16T13:58:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 181
tistoryUrl: "https://yeolceo.tistory.com/181"
tistoryCategory: "Branding/Resume"
tistoryTags: ["Formula","notion"]
tistoryPostedAt: "2023-07-16 13:58:50"
language: en
bloggerPostId: "2562354173476537504"
---
As you probably know, lots of developers use Notion for their resumes  
Notion has a feature called inline databases, which includes a property for displaying a specified date  
I entered my start and end dates for each job there. That's where the problem began

Notion has a feature called formula that lets you write script-based calculations  
So I wanted to record the duration as a formula  
I built a formula, but every example I found just computed the number of days as end date minus start date  
In other words, with a start date of 2022.01.01 and an end date of 2023.01.01, every blog's example formula gave you 365  
But I wanted it to show YYYY MM DD, or at least just check how many months and days

No matter what I tried, the approach was murky. You can't declare variables,  
and even when I broke the date into milliseconds, the displayed date came out relative to January 1, 1970 UTC

So I flipped my thinking: if I drop the leading digit of the year and only use the ones digit, I can display it the way I want  
If you're going to use this, I'd appreciate a like or a comment

```html
prop("to") ? 
	slice(
		concat(
			formatDate(
            	fromTimestamp(
                	dateBetween(
                    	prop("to"), prop("from"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1) 
    :slice(
    	concat(
        	formatDate(
            	fromTimestamp(
                	dateBetween(now(), prop("from"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1)

One-line version------------------------------                
prop("to") ? slice(concat(formatDate(fromTimestamp(dateBetween(prop("to"), prop("from"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1) : slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("from"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1)
```

Then you get a nice display like the one below  
It's based on the start and end dates, and if you're currently employed there, it uses now()  

The approach is a bit convoluted, but this is what I wanted to build, and even though it took a while, I'm happy I got it into a formula  
I couldn't find any examples like mine, so I'm writing this up

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/181/img.webp)

But what if you want to put this on your resume and also need a total? There's calculation within a single row,  
but I couldn't find a way to pull values from each row like in Excel  
There's a workaround, though: set the start date yourself  
Use if twice and create one hidden table. Then, for the row with no from, set the start date to now minus your total years of experience

Finally, handle the case where after 11 months the next month should show 0 months instead of 12, and the year should go up, and you're done

```html
if(empty(prop("from")) == true,
if(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("start_job"), "milliseconds")), "M") == "12", 
slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("start_job"), "milliseconds")), "YY [years] 0 [months] DD [days]")), 1),
slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("start_job"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1)), 
if(empty(prop("to")) == false, if(formatDate(fromTimestamp(dateBetween(dateSubtract(prop("to"), 1, "months"), prop("from"), "milliseconds")), "M") == "12", 
slice(concat(formatDate(fromTimestamp(dateBetween(prop("to"), prop("from"), "milliseconds")), "YY [years] 0 [months] DD [days]")), 1), 
slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(prop("to"), 1, "months"), prop("from"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1)), 
if(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("from"), "milliseconds")), "M") == "12", 
slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("from"), "milliseconds")), "YY [years] 0 [months] DD [days]")), 1), 
slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("from"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1))))
```

Formulas don't support line breaks, so you have to write them as a single line. Here's the one-line version too

```html
if(empty(prop("from")) == true,if(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("start_job"), "milliseconds")), "M") == "12", slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("start_job"), "milliseconds")), "YY [years] 0 [months] DD [days]")), 1),slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("start_job"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1)), if(empty(prop("to")) == false, if(formatDate(fromTimestamp(dateBetween(dateSubtract(prop("to"), 1, "months"), prop("from"), "milliseconds")), "M") == "12", slice(concat(formatDate(fromTimestamp(dateBetween(prop("to"), prop("from"), "milliseconds")), "YY [years] 0 [months] DD [days]")), 1), slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(prop("to"), 1, "months"), prop("from"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1)), if(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("from"), "milliseconds")), "M") == "12", slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("from"), "milliseconds")), "YY [years] 0 [months] DD [days]")), 1), slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("from"), "milliseconds")), "YY [years] MM [months] DD [days]")), 1))))
```
