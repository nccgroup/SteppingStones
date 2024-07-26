/**
 *  Plug-in offers the same functionality as `default` pagination type
 *  (see `pagingType` option) but with an input field for jumping pages, for use with bootstrap theme.
 *  A combination of Dist-DataTables-Bootstrap5/js/dataTables.bootstrap5.js and
 *  Plugins/pagination/input.js
 *
 *  @example
 *    $(document).ready(function() {
 *        $('#example').dataTable( {
 *            "pagingType": "bootstrap_input"
 *        } );
 *    } );
 */

(function ($) {
    /**
     * Add bootstrap themed input field (based on input.js) with addition UX tweaks of disabling for single
     * page tables and reacting to the enter key on text input.
     */
    function createInputElement(settings) {
        const pageInfo = $(settings.nTable).DataTable().page.info();
        const $input = $('<input>', {
            class: 'form-control rounded-0 text-end',
            type: 'number',
            min: 1,
            max: pageInfo.pages,
        }).val(pageInfo.page + 1);

        if (pageInfo.pages === 1) {
            $input.prop("disabled", true)
        }

        var changeHandler = function (e) {
            if (e.target.value === '' || e.target.value.match(/[^0-9]/)) {
                /* Nothing entered or non-numeric character */
                e.target.value = e.target.value.replace(/[^\d]/g, ''); // don't even allow anything but digits
                return;
            }

            const page = Number(e.target.value - 1);
            $(settings.nTable).DataTable().page(page).draw(false);
        };

        $input.on("change", changeHandler)
        $input.on('keyup', function (e) {
            if (e.key === 'Enter' || e.keyCode === 13) {
                changeHandler(e);
            }
        });

        return $input;
    }

    // Use "ellipsis" as a placeholder for where we want the input fields placing
    $.fn.DataTable.ext.pager.bootstrap_input = function() {
        return ['first', 'previous', 'ellipsis', 'next', 'last'];
    };

    /**
     * Render the pagination buttons as a series of <li> tags (as per dataTables.bootstrap5.js) but deviate when
     * we are asked to render the ellipsis.
     */
    $.fn.DataTable.ext.renderer.pagingButton.bootstrap = function (settings, buttonType, content, active, disabled) {
        var btnClasses = ['dt-paging-button', 'page-item'];

        if (active) {
            btnClasses.push('active');
        }

        if (disabled) {
            btnClasses.push('disabled');
        }

        var li = $('<li>').addClass(btnClasses.join(' '));
        var clicker;

        if (buttonType === 'ellipsis') {
            clicker = $('<div>', {class: 'input-group'})
                .append(createInputElement(settings))
                .append(
                    $('<span>', {class: 'input-group-text rounded-0'})
                        .text('of ' + $(settings.nTable).DataTable().page.info().pages)[0]
                )
                .appendTo(li);
        } else {
            clicker = $('<a>', {
                'href': disabled ? null : '#',
                'class': 'page-link'
            })
            .html(content)
            .appendTo(li);
        }

        return {
            display: li,
            clicker: clicker
        };
    }
})(jQuery);

