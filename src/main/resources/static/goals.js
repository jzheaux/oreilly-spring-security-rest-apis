const ready = () => {
    goalcontroller.list();

    $("#logout input").val(security.csrf.value);
    $("#logout a").on("click", () => { $("#logout form").submit(); });
    $("#new button").on("click", goalcontroller.add);
    $("#new input").keypress((e) => { if (e.which === 13) { goalcontroller.add() }});
};

const goalcontroller = {
    root: "http://localhost:8080",
    list : () =>
        $.get(goalcontroller.root + "/goals", (goals) => {
            for (let goal of goals) {
                goalcontroller._upsertGoal(goal);
            }
        }),
    add: () =>
        $.ajax({
            type: "POST",
            url: goalcontroller.root + "/goal",
            data: $("#new input").val(),
            contentType: "application/json"
        }).done((goal) => {
            goalcontroller._upsertGoal(goal);
            $("#new input").val("");
        }),
    complete : (id) =>
        $.ajax({
            type : "PUT",
            url : goalcontroller.root + "/goal/" + id + "/complete",
        }).done((goal) => {
            goalcontroller._upsertGoal(goal);
        }),
    _upsertGoal : (goal) => {
        let li = $("#goals li").filter(function() { return $(this).data("id") === goal.id; });
        if (li.length === 0) {
            li = $("<li class='list-group-item'>");
            li.data("id", goal.id);
            li.click(() => {
                goalcontroller.complete(li.data("id"));
            });
            li.hover(() => {
                $(this).toggleClass("active");
            });
            $("#goals").append(li);
        }
        li.text(goal.text);
        if (goal.completed) {
            li.addClass("completed");
        } else {
            li.removeClass("completed");
        }
        $("#welcome").html(goal.owner + "'s Goals")
    }
};