$(document).ready(function () {
    $(".time_list li,.loc_list li").click(function () {//点击的时候给当前这个加上，其他的移除
        $(this).addClass("active").siblings("li").removeClass("active");
    });

    $("#oranger li").on("mouseover", function () { //给a标签添加事件
        var index = $(this).index();  //获取当前a标签的个数
        $(this).parent().parent().next().find(".box").hide().eq(index).show(); //返回上一层，在下面查找css名为box隐藏，然后选中的显示
    });
});

// 调取对比信息
