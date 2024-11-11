pdfMake.preserveLeadingSpaces = true

function pdfExportCustomize(doc, config, dt) {
    pdfMake.fonts = {
        RobotoMono: {
            normal: eventTableConfig.monospaceFontURL,
        },
        Roboto: {
            normal: 'https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.1.66/fonts/Roboto/Roboto-Regular.ttf',
            bold: 'https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.1.66/fonts/Roboto/Roboto-Medium.ttf',
        },
    }

    doc.styles['terminal'] = {
        font: 'RobotoMono',
        bold: false
    }

    for (const row of doc.content[1].table.body) {
        let description = row[eventTableConfig.descriptionColumn]  // column of each row that should be "Description"
        const parts = description.text.split("{monospace}")
        if (parts.length > 1) {
            // Attach 'terminal' style to everything after the first "\n\n"
            description.text = [parts[0], parts[0].length ? "\n\n" : "", {
                text: parts.slice(1).join("\n\n"),
                style: 'terminal',
                preserveLeadingSpaces: true
            }]
        }
    }

    // Ensure the main text column doesn't stretch when given long content
    doc.content[1].table.widths = Array(eventTableConfig.totalColumns).fill("auto")
    doc.content[1].table.widths[eventTableConfig.descriptionColumn] = 400
    // Sprinkle in some corporate branding
    doc.footer = function (currentPage, pageCount) {
        return [
            {
                canvas: [
                    {type: 'line', x1: 40, y1: 0, x2: 800, y2: 0, lineWidth: 0.5, lineColor: '#242C7A'}
                ]
            },
            {
                columns: [
                    currentPage.toString() + ' / ' + pageCount,
                    {svg: eventTableConfig.brandingSVG, alignment: 'center'},
                    {text: eventTableConfig.brandingText, alignment: 'right'},
                ],
                margin: [40, 10],
            },
        ]
    }
}

function pdfExportAction (e, dt, node, config, cb) {
    let outer_dt = dt;
    let outer_config = config;
    let orig_len = dt.page.len();
    let outer_cb = cb;

    doExport = function (e, _dt, node, _config, cb) {
        // Deregister the event handler
        dt.off('draw', doExport);
        // Trigger the print action
        $.fn.dataTable.ext.buttons.pdfHtml5.action.call(outer_dt.button(), e, outer_dt, node, outer_config, outer_cb);
        // Redraw the table at the original page size
        dt.page.len(orig_len).draw();
    }

    // Register an event handler to print the table once all the data is loaded
    dt.on( 'draw', doExport )
    // Trigger a non-paginated table draw
    dt.page.len(-1).draw();
}

function descriptionRender (data, type, row) {
    if (type === "export") {
        // When exporting to PDF, before the HTML is stripped and passed to pdfMake,
        // add a double new line to show where the <div>s end. Used by customize function above.
        return data.split(/<div class=['"](?:out|in)put['"]>/).join("{monospace}")
    } else {
        return data;
    }
}

function tableDrawCallback (settings) {
      $('.output').expander({slicePoint: 200, normalizeWhitespace: false, detailPrefix: '',});
  }