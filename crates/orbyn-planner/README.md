# orbyn-planner

Planner rules: tasks and events, lists, and repeat rules with "this one only" (skip) and "this and following" (split) edits. Pure and synchronous, so it runs the same on every device and in WebAssembly. Items convert to and from `orbyn_sync::Fields`, with checklist entries and skips as fields of their own so concurrent edits merge. Events have dates only so far; start and end times, all-day ranges and time zones come with the calendar slice.
